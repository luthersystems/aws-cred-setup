package run

import (
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mdp/qrterminal"
)

func userName(sess client.ConfigProvider) (string, error) {
	stsService := sts.New(sess)
	identInput := &sts.GetCallerIdentityInput{}
	identResult, err := stsService.GetCallerIdentity(identInput)
	if err != nil {
		return "", err
	}

	arnComps := strings.Split(*identResult.Arn, ":")
	lastArnComp := arnComps[len(arnComps)-1]
	if !strings.HasPrefix(lastArnComp, "user/") {
		return "", fmt.Errorf("The available credentials are for a non-user ARN: %s", *identResult.Arn)
	}
	return strings.TrimPrefix(lastArnComp, "user/"), nil
}

func serialCleaner(iamService *iam.IAM, setupError *error) func(string) {
	return func(serial string) {
		if *setupError == nil {
			return
		}
		fmt.Println("Setup incomplete, deleting unused MFA device.")
		input := &iam.DeleteVirtualMFADeviceInput{
			SerialNumber: aws.String(serial),
		}
		_, err := iamService.DeleteVirtualMFADevice(input)
		if err != nil {
			fmt.Printf("Failed to clean up MFA device.  Manual intervention required.  Error: %v", err)
		}
	}
}

func MFASetup() (err error) {
	sess := session.Must(session.NewSession())
	iamService := iam.New(sess)
	cleanup := serialCleaner(iamService, &err)

	userName, err := userName(sess)
	if err != nil {
		return err
	}
	fmt.Printf("Setting up MFA for user: %s.  Continue? <enter>", userName)
	fmt.Scanln()
	createInput := &iam.CreateVirtualMFADeviceInput{
		VirtualMFADeviceName: aws.String(userName),
	}
	createResult, err := iamService.CreateVirtualMFADevice(createInput)
	if err != nil {
		return err
	}
	serial := *createResult.VirtualMFADevice.SerialNumber
	defer cleanup(serial)

	seed := string(createResult.VirtualMFADevice.Base32StringSeed)
	qrString := fmt.Sprintf("otpauth://totp/Amazon%%20Web%%20Services:%s@luther?secret=%s&issuer=Amazon%%20Web%%20Services", userName, seed)
	qrterminal.GenerateHalfBlock(qrString, qrterminal.L, os.Stdout)

	var code1, code2 string
	fmt.Printf("Enter two consecutive Authenticator codes to enroll\n\n")
	fmt.Printf("code 1: ")
	if _, err := fmt.Scanln(&code1); err != nil {
		return err
	}
	fmt.Printf("code 2: ")
	if _, err := fmt.Scanln(&code2); err != nil {
		return err
	}
	enableInput := &iam.EnableMFADeviceInput{
		SerialNumber:        aws.String(serial),
		UserName:            aws.String(userName),
		AuthenticationCode1: aws.String(code1),
		AuthenticationCode2: aws.String(code2),
	}
	if _, err := iamService.EnableMFADevice(enableInput); err != nil {
		return err
	}

	return nil
}
