# Windows Patching Pipeline

## Local Environment Requirements

You need to have the following dependencies in place:

- AWS Account
- aws-sam-cli [here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- AWS credentials and profiles for each environment under ~/.aws/config [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- cfn-lint [here](https://github.com/aws-cloudformation/cfn-lint)

## Getting Started

Set up AWS SAM CLI configuration file and update the configuration options accordingly. More information can be found [here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-config.html).

```sh
mv samconfig.toml.example samconfig.toml
```

Build the SAM Stack

```sh
sam build
```

Package the SAM stack

```sh
# Needs AWS profile set
sam package --resolve-s3 --force-upload -t template.yml
```

Deploy the SAM stack

```sh
# Needs AWS profile set
sam deploy --force-upload
```