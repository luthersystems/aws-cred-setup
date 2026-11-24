package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/mdp/qrterminal"
)

// defaultRegion is used when no region is configured. IAM is global, and
// STS is reached through us-east-1 here (see stsRegion), so in the
// commercial partition the region does not change which account or user
// the calls see. The v1 SDK worked with no region for these two services;
// the v2 SDK refuses to resolve an endpoint without one, so this fallback
// keeps a bare `aws configure` (keys only) working as before. GovCloud and
// China users must set AWS_REGION, as they had to with v1.
const defaultRegion = "us-east-1"

// iamAPI is the part of the IAM client this tool calls. It is an interface
// so tests can use a fake in place of AWS.
type iamAPI interface {
	CreateVirtualMFADevice(ctx context.Context, in *iam.CreateVirtualMFADeviceInput, opts ...func(*iam.Options)) (*iam.CreateVirtualMFADeviceOutput, error)
	EnableMFADevice(ctx context.Context, in *iam.EnableMFADeviceInput, opts ...func(*iam.Options)) (*iam.EnableMFADeviceOutput, error)
	DeleteVirtualMFADevice(ctx context.Context, in *iam.DeleteVirtualMFADeviceInput, opts ...func(*iam.Options)) (*iam.DeleteVirtualMFADeviceOutput, error)
}

// stsAPI is the part of the STS client this tool calls.
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, opts ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// loadConfig reads credentials the way the v1 session did.
//
// v1 read ~/.aws/config, AWS_DEFAULT_REGION and AWS_DEFAULT_PROFILE only
// when AWS_SDK_LOAD_CONFIG was true; v2 always reads them. A profile in
// ~/.aws/config often assumes a role, and a role has no MFA device to set
// up, so reading it by default would break users v1 served. So without
// AWS_SDK_LOAD_CONFIG this loads only the credentials file, AWS_PROFILE
// and AWS_REGION. One difference stays: v2 reads AWS_DEFAULT_PROFILE when
// AWS_PROFILE is unset.
func loadConfig(ctx context.Context) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error
	if loadShared, _ := strconv.ParseBool(os.Getenv("AWS_SDK_LOAD_CONFIG")); !loadShared {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = defaultRegion
		}
		opts = append(opts,
			// A non-nil empty list means "no config file", not the default.
			config.WithSharedConfigFiles([]string{}),
			config.WithRegion(region),
		)
		// Only pass AWS_PROFILE when it is set: an explicit profile that
		// is missing from the credentials file is an error, and a user
		// with keys in the environment and no files must still work.
		if profile := os.Getenv("AWS_PROFILE"); profile != "" {
			opts = append(opts, config.WithSharedConfigProfile(profile))
		}
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
	return cfg, nil
}

// stsRegion picks the region for the STS client. v1 sent STS calls in the
// commercial regions to the global endpoint, which works even where a
// regional STS endpoint is turned off or the region is not opted in. v2
// only uses regional endpoints, so commercial regions use us-east-1, the
// region of the global endpoint. Other partitions (China, GovCloud, ISO)
// keep their own region, as v1 did.
func stsRegion(region string) string {
	if strings.HasPrefix(region, "cn-") || strings.HasPrefix(region, "us-gov-") || strings.Contains(region, "-iso") {
		return region
	}
	return defaultRegion
}

func userName(ctx context.Context, stsService stsAPI) (string, error) {
	identResult, err := stsService.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}

	arn := aws.ToString(identResult.Arn)
	arnComps := strings.Split(arn, ":")
	lastArnComp := arnComps[len(arnComps)-1]
	if !strings.HasPrefix(lastArnComp, "user/") {
		return "", fmt.Errorf("available credentials are for a non-user ARN: %s", arn)
	}
	return strings.TrimPrefix(lastArnComp, "user/"), nil
}

// deleteUnusedDevice removes an MFA device that was created but not
// enabled. The device name is the user name, so a device left behind makes
// the next attempt fail. It does not run if the process is killed (Ctrl-C).
func (s *setup) deleteUnusedDevice(ctx context.Context, serial string) {
	_, _ = fmt.Fprintln(s.out, "Setup incomplete, deleting unused MFA device.")
	input := &iam.DeleteVirtualMFADeviceInput{
		SerialNumber: aws.String(serial),
	}
	_, err := s.iam.DeleteVirtualMFADevice(ctx, input)
	if err != nil {
		_, _ = fmt.Fprintf(s.out, "Failed to clean up MFA device.  Manual intervention required.  Error: %v\n", err)
	}
}

// MFASetup enables MFA for the user
func MFASetup() error {
	ctx := context.Background()
	cfg, err := loadConfig(ctx)
	if err != nil {
		return err
	}
	s := &setup{
		iam: iam.NewFromConfig(cfg),
		sts: sts.NewFromConfig(cfg, func(o *sts.Options) { o.Region = stsRegion(cfg.Region) }),
		in:  os.Stdin,
		out: os.Stdout,
	}
	return s.run(ctx)
}

// setup holds the AWS clients and the terminal of one MFA setup. Tests
// build one with fakes and a buffer to drive the whole flow.
type setup struct {
	iam iamAPI
	sts stsAPI
	in  io.Reader
	out io.Writer
}

func (s *setup) run(ctx context.Context) error {
	userName, err := userName(ctx, s.sts)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(s.out, "Setting up MFA for user: %s.  Continue? <enter>", userName)
	if _, err = fmt.Fscanln(s.in); err != nil {
		return err
	}
	createInput := &iam.CreateVirtualMFADeviceInput{
		VirtualMFADeviceName: aws.String(userName),
	}
	createResult, err := s.iam.CreateVirtualMFADevice(ctx, createInput)
	if err != nil {
		return err
	}
	device := createResult.VirtualMFADevice
	if device == nil || device.SerialNumber == nil {
		// Nothing to enroll or delete. v1 would have panicked here.
		return errors.New("CreateVirtualMFADevice returned no device")
	}

	// From here on a failure must delete the new device.
	err = s.enroll(ctx, userName, device)
	if err != nil {
		s.deleteUnusedDevice(ctx, *device.SerialNumber)
	}
	return err
}

// enroll shows the device's QR code, reads two codes and enables the device.
func (s *setup) enroll(ctx context.Context, userName string, device *iamtypes.VirtualMFADevice) error {
	serial := aws.ToString(device.SerialNumber)
	seed := string(device.Base32StringSeed)
	qrString := fmt.Sprintf("otpauth://totp/Amazon%%20Web%%20Services:%s@luther?secret=%s&issuer=Amazon%%20Web%%20Services", userName, seed)
	qrterminal.GenerateHalfBlock(qrString, qrterminal.L, s.out)

	var code1, code2 string
	_, _ = fmt.Fprintf(s.out, "Enter two consecutive Authenticator codes to enroll\n\n")
	_, _ = fmt.Fprintf(s.out, "code 1: ")
	if _, err := fmt.Fscanln(s.in, &code1); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(s.out, "code 2: ")
	if _, err := fmt.Fscanln(s.in, &code2); err != nil {
		return err
	}
	enableInput := &iam.EnableMFADeviceInput{
		SerialNumber:        aws.String(serial),
		UserName:            aws.String(userName),
		AuthenticationCode1: aws.String(code1),
		AuthenticationCode2: aws.String(code2),
	}
	_, err := s.iam.EnableMFADevice(ctx, enableInput)
	return err
}
