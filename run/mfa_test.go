package run

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeSTS struct {
	arn string
	err error
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Arn: aws.String(f.arn)}, nil
}

type fakeIAM struct {
	createdName string
	enabled     *iam.EnableMFADeviceInput
	deleted     string
	createErr   error
	enableErr   error
	deleteErr   error
	noDevice    bool
}

const testSerial = "arn:aws:iam::123456789012:mfa/alice"

func (f *fakeIAM) CreateVirtualMFADevice(_ context.Context, in *iam.CreateVirtualMFADeviceInput, _ ...func(*iam.Options)) (*iam.CreateVirtualMFADeviceOutput, error) {
	f.createdName = aws.ToString(in.VirtualMFADeviceName)
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.noDevice {
		return &iam.CreateVirtualMFADeviceOutput{}, nil
	}
	return &iam.CreateVirtualMFADeviceOutput{VirtualMFADevice: &iamtypes.VirtualMFADevice{
		SerialNumber:     aws.String(testSerial),
		Base32StringSeed: []byte("SEED"),
	}}, nil
}

func (f *fakeIAM) EnableMFADevice(_ context.Context, in *iam.EnableMFADeviceInput, _ ...func(*iam.Options)) (*iam.EnableMFADeviceOutput, error) {
	f.enabled = in
	if f.enableErr != nil {
		return nil, f.enableErr
	}
	return &iam.EnableMFADeviceOutput{}, nil
}

func (f *fakeIAM) DeleteVirtualMFADevice(_ context.Context, in *iam.DeleteVirtualMFADeviceInput, _ ...func(*iam.Options)) (*iam.DeleteVirtualMFADeviceOutput, error) {
	f.deleted = aws.ToString(in.SerialNumber)
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &iam.DeleteVirtualMFADeviceOutput{}, nil
}

func TestUserName(t *testing.T) {
	ctx := context.Background()
	name, err := userName(ctx, &fakeSTS{arn: "arn:aws:iam::123456789012:user/alice"})
	if err != nil || name != "alice" {
		t.Fatalf("userName = %q, %v; want alice, nil", name, err)
	}
	// An assumed role is not a user, so it has no MFA device to set up.
	_, err = userName(ctx, &fakeSTS{arn: "arn:aws:sts::123456789012:assumed-role/admin/s"})
	if err == nil || !strings.Contains(err.Error(), "non-user ARN") {
		t.Fatalf("role ARN: err = %v; want non-user ARN error", err)
	}
	wantErr := errors.New("no creds")
	if _, err = userName(ctx, &fakeSTS{err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("STS error: err = %v; want %v", err, wantErr)
	}
}

func TestMFASetupEnablesDevice(t *testing.T) {
	fi := &fakeIAM{}
	var out bytes.Buffer
	in := strings.NewReader("\n111111\n222222\n")
	err := (&setup{iam: fi, sts: &fakeSTS{arn: "arn:aws:iam::1:user/alice"}, in: in, out: &out}).run(context.Background())
	if err != nil {
		t.Fatalf("mfaSetup: %v", err)
	}
	if fi.createdName != "alice" {
		t.Errorf("device name = %q; want alice", fi.createdName)
	}
	e := fi.enabled
	if e == nil || aws.ToString(e.UserName) != "alice" || aws.ToString(e.SerialNumber) != testSerial ||
		aws.ToString(e.AuthenticationCode1) != "111111" || aws.ToString(e.AuthenticationCode2) != "222222" {
		t.Errorf("EnableMFADevice input = %+v", e)
	}
	if fi.deleted != "" {
		t.Errorf("deleted %q after a successful setup", fi.deleted)
	}
	if !strings.Contains(out.String(), "Setting up MFA for user: alice") {
		t.Errorf("output lacks the prompt: %q", out.String())
	}
}

// A failed enable must delete the new device, or the next run fails
// because a device with the user's name already exists.
func TestMFASetupDeletesDeviceOnFailure(t *testing.T) {
	wantErr := errors.New("invalid code")
	fi := &fakeIAM{enableErr: wantErr}
	in := strings.NewReader("\n111111\n222222\n")
	err := (&setup{iam: fi, sts: &fakeSTS{arn: "arn:aws:iam::1:user/alice"}, in: in, out: &bytes.Buffer{}}).run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want %v", err, wantErr)
	}
	if fi.deleted != testSerial {
		t.Errorf("deleted = %q; want %q", fi.deleted, testSerial)
	}
}

func TestMFASetupDeletesDeviceOnMissingCode(t *testing.T) {
	fi := &fakeIAM{}
	// Input ends before the second code.
	in := strings.NewReader("\n111111\n")
	err := (&setup{iam: fi, sts: &fakeSTS{arn: "arn:aws:iam::1:user/alice"}, in: in, out: &bytes.Buffer{}}).run(context.Background())
	if err == nil {
		t.Fatal("mfaSetup succeeded without a second code")
	}
	if fi.enabled != nil {
		t.Error("EnableMFADevice was called without a second code")
	}
	if fi.deleted != testSerial {
		t.Errorf("deleted = %q; want %q", fi.deleted, testSerial)
	}
}

// isolateAWSConfig points the SDK at empty config files and clears the
// region variables, so the test does not read the developer's ~/.aws.
func isolateAWSConfig(t *testing.T, configBody string) string {
	t.Helper()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config")
	if err := os.WriteFile(cfgFile, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(dir, "credentials")
	if err := os.WriteFile(credFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgFile)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credFile)
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	// Clear every other variable these tests depend on, and the ones that
	// can make LoadDefaultConfig fail on a developer machine.
	for _, k := range []string{
		"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_SDK_LOAD_CONFIG",
		"AWS_CA_BUNDLE", "AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT",
		"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_IAM",
		"AWS_EC2_METADATA_DISABLED",
	} {
		t.Setenv(k, "")
	}
	return credFile
}

func TestLoadConfigFallsBackToGlobalRegion(t *testing.T) {
	isolateAWSConfig(t, "")
	cfg, err := loadConfig(context.Background())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Region != defaultRegion {
		t.Errorf("region = %q; want %q", cfg.Region, defaultRegion)
	}
}

func TestLoadConfigKeepsConfiguredRegion(t *testing.T) {
	isolateAWSConfig(t, "")
	t.Setenv("AWS_REGION", "eu-west-2")
	cfg, err := loadConfig(context.Background())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Region != "eu-west-2" {
		t.Errorf("region = %q; want eu-west-2", cfg.Region)
	}
}

// Without AWS_SDK_LOAD_CONFIG the v1 SDK ignored ~/.aws/config and
// AWS_DEFAULT_REGION. A role profile there must not replace the user's
// own keys, so the config file stays unread here too.
func TestLoadConfigIgnoresConfigFileByDefault(t *testing.T) {
	isolateAWSConfig(t, "[default]\nregion = ap-south-1\nrole_arn = arn:aws:iam::1:role/admin\nsource_profile = default\n")
	t.Setenv("AWS_DEFAULT_REGION", "eu-central-1")
	cfg, err := loadConfig(context.Background())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Region != defaultRegion {
		t.Errorf("region = %q; want %q", cfg.Region, defaultRegion)
	}
}

// With AWS_SDK_LOAD_CONFIG=1 the config file and AWS_PROFILE apply, as
// in v1.
func TestLoadConfigUsesProfileWithLoadConfig(t *testing.T) {
	isolateAWSConfig(t, "[profile work]\nregion = ap-south-1\n")
	t.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	t.Setenv("AWS_PROFILE", "work")
	cfg, err := loadConfig(context.Background())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Region != "ap-south-1" {
		t.Errorf("region = %q; want ap-south-1", cfg.Region)
	}
}

// AWS_PROFILE picks a section of the credentials file, as in v1.
func TestLoadConfigUsesCredentialsProfile(t *testing.T) {
	credFile := isolateAWSConfig(t, "")
	body := "[work]\naws_access_key_id = AKIDWORK\naws_secret_access_key = secret\n"
	if err := os.WriteFile(credFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_PROFILE", "work")
	cfg, err := loadConfig(context.Background())
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if creds.AccessKeyID != "AKIDWORK" {
		t.Errorf("access key = %q; want AKIDWORK", creds.AccessKeyID)
	}
}

func TestSTSRegion(t *testing.T) {
	for region, want := range map[string]string{
		"us-east-1":     "us-east-1",
		"eu-west-2":     "us-east-1",
		"me-south-1":    "us-east-1",
		"us-gov-west-1": "us-gov-west-1",
		"cn-north-1":    "cn-north-1",
		"us-iso-east-1": "us-iso-east-1",
	} {
		if got := stsRegion(region); got != want {
			t.Errorf("stsRegion(%q) = %q; want %q", region, got, want)
		}
	}
}

func TestMFASetupCreateFailure(t *testing.T) {
	wantErr := errors.New("EntityAlreadyExists")
	fi := &fakeIAM{createErr: wantErr}
	err := (&setup{iam: fi, sts: &fakeSTS{arn: "arn:aws:iam::1:user/alice"}, in: strings.NewReader("\n"), out: &bytes.Buffer{}}).run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want %v", err, wantErr)
	}
	if fi.enabled != nil || fi.deleted != "" {
		t.Errorf("enable or delete ran after a failed create: %+v", fi)
	}
}

func TestMFASetupNoDevice(t *testing.T) {
	fi := &fakeIAM{noDevice: true}
	err := (&setup{iam: fi, sts: &fakeSTS{arn: "arn:aws:iam::1:user/alice"}, in: strings.NewReader("\n"), out: &bytes.Buffer{}}).run(context.Background())
	if err == nil {
		t.Fatal("run succeeded without a device")
	}
	if fi.enabled != nil || fi.deleted != "" {
		t.Errorf("enable or delete ran without a device: %+v", fi)
	}
}
