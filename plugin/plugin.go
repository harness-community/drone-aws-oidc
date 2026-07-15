package plugin

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sirupsen/logrus"
)

// Args provides plugin execution arguments.
type Args struct {
	Level            string `envconfig:"PLUGIN_LOG_LEVEL"`
	RoleARN          string `envconfig:"PLUGIN_IAMROLEARN"`
	OIDCTokenID      string `envconfig:"PLUGIN_OIDC_TOKEN_ID"`
	RoleSessionName  string `envconfig:"PLUGIN_ROLE_SESSION_NAME"`
	DurationSeconds  int64  `envconfig:"PLUGIN_DURATION"`
	Region           string `envconfig:"PLUGIN_REGION"`
}

// Exec executes the plugin.
func Exec(ctx context.Context, args Args) error {
	if args.RoleSessionName == "" {
		args.RoleSessionName = "harness-aws-oidc"
	}

	// Configure the AWS session. By default (no region) the SDK resolves STS to
	// the commercial global endpoint (sts.amazonaws.com, partition "aws"), which
	// cannot validate tokens issued by an OIDC provider in another partition such
	// as AWS GovCloud (aws-us-gov). Setting the region routes STS to that
	// partition's regional endpoint (e.g. sts.us-gov-west-1.amazonaws.com) so
	// GovCloud and other regional deployments work.
	cfg := aws.Config{
		STSRegionalEndpoint: endpoints.RegionalSTSEndpoint,
	}
	if args.Region != "" {
		cfg.Region = aws.String(args.Region)
	}

	sess, err := session.NewSession(&cfg)
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %w", err)
	}

	svc := sts.New(sess)

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(args.RoleARN),
		RoleSessionName:  aws.String(args.RoleSessionName),
		WebIdentityToken: aws.String(args.OIDCTokenID),
		DurationSeconds:  aws.Int64(args.DurationSeconds),
	}

	result, err := svc.AssumeRoleWithWebIdentity(input)
	if err != nil {
		return fmt.Errorf("failed to assume role with web identity: %w", err)
	}

	// Write the AWS credentials to the output file
	if err := WriteEnvToFile("AWS_ACCESS_KEY_ID", *result.Credentials.AccessKeyId); err != nil {
		return err
	}
	if err := WriteEnvToFile("AWS_SECRET_ACCESS_KEY", *result.Credentials.SecretAccessKey); err != nil {
		return err
	}
	if err := WriteEnvToFile("AWS_SESSION_TOKEN", *result.Credentials.SessionToken); err != nil {
		return err
	}

	logrus.Infof("Retreieved AWS temporary credentials successfully.")

	return nil
}

func WriteEnvToFile(key, value string) error {
	outputFile, err := os.OpenFile(os.Getenv("HARNESS_OUTPUT_SECRET_FILE"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer outputFile.Close()

	_, err = fmt.Fprintf(outputFile, "%s=%s\n", key, value)
	if err != nil {
		return fmt.Errorf("failed to write to env: %w", err)
	}

	return nil
}
