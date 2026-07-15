# drone-aws-oidc

- [Synopsis](#Synopsis)
- [Parameters](#Parameters)
- [Notes](#Notes)
- [Plugin Image](#Plugin-Image)
- [Examples](#Examples)

## Synopsis

This plugin generates AWS temporary credentials (Access Key ID, Secret Access Key, and Session Token) through OIDC token exchange using AWS STS `AssumeRoleWithWebIdentity`. These credentials are outputted as secret environment variables that can be utilized in subsequent pipeline steps to interact with AWS services through the AWS CLI or API.

To learn how to utilize Drone plugins in Harness CI, please consult the provided [documentation](https://developer.harness.io/docs/continuous-integration/use-ci/use-drone-plugins/run-a-drone-plugin-in-ci).

## Parameters

| Parameter                                                                                                                          | Choices/<span style="color:blue;">Defaults</span> | Comments                                                                |
| :--------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------ | ----------------------------------------------------------------------- |
| iamrolearn <span style="font-size: 10px"><br/>`string`</span> <span style="color:red; font-size: 10px">`required`</span>           |                                                   | The ARN of the IAM role to assume via OIDC.                             |
| role_session_name <span style="font-size: 10px"><br/>`string`</span>                                                               | Default: `harness-aws-oidc`                       | An identifier for the assumed role session.                             |
| duration <span style="font-size: 10px"><br/>`integer`</span>                                                                       | Default: `3600`                                   | The duration of the temporary credentials in seconds (max 43200).       |
| region <span style="font-size: 10px"><br/>`string`</span>                                                                          |                                                   | AWS region used to resolve the STS endpoint. Required for non-commercial partitions such as AWS GovCloud (e.g. `us-gov-west-1`). If unset, the commercial global endpoint (`sts.amazonaws.com`) is used. |
| log_level <span style="font-size: 10px"><br/>`string`</span>                                                                       | Default: `info`                                   | Log level for plugin output. Choices: `debug`, `trace`, or default.     |

## Notes

- `PLUGIN_OIDC_TOKEN_ID` is not manually configured; instead, the CI stage recognizes that the Plugin Step involving the `drone-aws-oidc` plugin is being executed. If this is the case, the CI stage calls the OIDC token generator API from the platform and sets the generated token in the `PLUGIN_OIDC_TOKEN_ID` environment variable.

- Please provide the `duration` in seconds. For example, the default value is 1 hour (3600 seconds). The maximum session duration depends on the IAM role's configuration (up to 12 hours / 43200 seconds). You can configure this via the role's "Maximum session duration" setting in AWS IAM.

- **AWS GovCloud / non-commercial partitions:** the OIDC token, the IAM role, and the STS endpoint must all live in the same partition. If your OIDC provider and role are in GovCloud (role ARN begins with `arn:aws-us-gov:`), set `region` to a GovCloud region (e.g. `us-gov-west-1`) so the plugin calls the GovCloud STS endpoint. Without it, the plugin defaults to the commercial endpoint and returns `InvalidIdentityToken` because the commercial partition cannot validate a GovCloud-issued token.

- The plugin outputs the following credentials as **secret** environment variables (written to `HARNESS_OUTPUT_SECRET_FILE`), accessible in subsequent pipeline steps:
  - `AWS_ACCESS_KEY_ID` — accessed via `<+steps.STEP_ID.output.outputVariables.AWS_ACCESS_KEY_ID>`
  - `AWS_SECRET_ACCESS_KEY` — accessed via `<+steps.STEP_ID.output.outputVariables.AWS_SECRET_ACCESS_KEY>`
  - `AWS_SESSION_TOKEN` — accessed via `<+steps.STEP_ID.output.outputVariables.AWS_SESSION_TOKEN>`

- The `role_session_name` is useful for tracking and auditing. It appears in AWS CloudTrail logs, helping you identify which pipeline or step assumed the role.

## Plugin Image

The plugin `plugins/aws-oidc` is available for the following architectures:

| OS            | Tag                                |
| ------------- | ---------------------------------- |
| latest        | `linux-amd64/arm64, windows-amd64` |
| linux/amd64   | `linux-amd64`                      |
| linux/arm64   | `linux-arm64`                      |
| windows/amd64 | `windows-amd64`                    |

## Examples

```yaml
# Basic usage - assume an IAM role via OIDC
- step:
    type: Plugin
    name: drone-aws-oidc-plugin
    identifier: drone_aws_oidc_plugin
    spec:
        connectorRef: harness-docker-connector
        image: plugins/aws-oidc
        settings:
            iamrolearn: arn:aws:iam::123456789012:role/my-oidc-role

# With custom session duration (2 hours)
- step:
    type: Plugin
    name: drone-aws-oidc-plugin
    identifier: drone_aws_oidc_plugin
    spec:
        connectorRef: harness-docker-connector
        image: plugins/aws-oidc
        settings:
            iamrolearn: arn:aws:iam::123456789012:role/my-oidc-role
            duration: 7200
            role_session_name: my-deploy-session

# Run step to use the AWS credentials (e.g., list S3 buckets)
- step:
    type: Run
    name: List S3 Buckets
    identifier: list_s3_buckets
    spec:
        shell: Sh
        command: |-
            export AWS_ACCESS_KEY_ID=<+steps.drone_aws_oidc_plugin.output.outputVariables.AWS_ACCESS_KEY_ID>
            export AWS_SECRET_ACCESS_KEY=<+steps.drone_aws_oidc_plugin.output.outputVariables.AWS_SECRET_ACCESS_KEY>
            export AWS_SESSION_TOKEN=<+steps.drone_aws_oidc_plugin.output.outputVariables.AWS_SESSION_TOKEN>
            aws s3 ls

# Run step to use the AWS credentials with curl (e.g., describe EC2 instances)
- step:
    type: Run
    name: Describe EC2 Instances
    identifier: describe_ec2
    spec:
        shell: Sh
        command: |-
            export AWS_ACCESS_KEY_ID=<+steps.drone_aws_oidc_plugin.output.outputVariables.AWS_ACCESS_KEY_ID>
            export AWS_SECRET_ACCESS_KEY=<+steps.drone_aws_oidc_plugin.output.outputVariables.AWS_SECRET_ACCESS_KEY>
            export AWS_SESSION_TOKEN=<+steps.drone_aws_oidc_plugin.output.outputVariables.AWS_SESSION_TOKEN>
            aws ec2 describe-instances --region us-east-1
```

> 
