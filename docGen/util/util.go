package util

import (
	"fmt"
	"regexp"
	"strings"
)

var categoryRemap = map[string]string{
	"cloudwatchlogs":        "Cloudwatch",
	"configservice":         "Config",
	"containerregistry":     "Container",
	"elbv2":                 "ELB",
	"kinesis video streams": "Kinesis",
	"lookoutequipment":      "Lookout",
	"lookoutmetrics":        "Lookout",
	"appservice":            "App Service",
	"repos":                 "Repositories",
	"apigateway":            "API Gateway",
	"codebuild":             "Code Build",
}

var acronyms = []string{
	"ack",
	"aks",
	"acl",
	"acm",
	"alb",
	"api",
	"apt",
	"arn",
	"aws",
	"cis",
	"clb",
	"cd",
	"cdn",
	"cidr",
	"cmd",
	"cpu",
	"db",
	"dnf",
	"dms",
	"dns",
	"ebs",
	"ec2",
	"ecr",
	"ecs",
	"efs",
	"eks",
	"elb",
	"emr",
	"es",
	"fsx",
	"gcr",
	"gid",
	"gke",
	"http",
	"http2",
	"https",
	"iam",
	"im",
	"imds",
	"ip",
	"ipc",
	"ips",
	"kms",
	"lb",
	"md5",
	"mfa",
	"mq",
	"msk",
	"mwaa",
	"nsa",
	"oss",
	"oke",
	"qldb",
	"pid",
	"pss",
	"ram",
	"rbac",
	"rdp",
	"rds",
	"rsa",
	"sam",
	"ses",
	"sgr",
	"sha1",
	"sha256",
	"sns",
	"sql",
	"sqs",
	"ssh",
	"ssm",
	"tls",
	"ubla",
	"uid",
	"vm",
	"vpc",
	"vtpm",
	"waf",
}

var specials = map[string]string{
	"actiontrail":    "ActionTrail",
	"dynamodb":       "DynamoDB",
	"documentdb":     "DocumentDB",
	"mysql":          "MySQL",
	"postgresql":     "PostgreSQL",
	"acls":           "ACLs",
	"ips":            "IPs",
	"bigquery":       "BigQuery",
	"selinux":        "SELinux",
	"cloudformation": "CloudFormation",
	"cloudfront":     "CloudFront",
	"cloudtrail":     "CloudTrail",
	"cloudwatch":     "CloudWatch",
	"codeartifact":   "Code Artifact",
	"codebuild":      "Code Build",
	"codepipeline":   "Code Pipeline",
	"codestar":       "Code Star",
	"xray":           "XRay",
	"memorydb":       "MemoryDB",
	"rh":             "RedHat",
}

func Nicify(input string) string {
	input = strings.ToLower(input)
	for replace, with := range specials {
		input = regexp.MustCompile(fmt.Sprintf("\\b%s\\b", replace)).ReplaceAllString(input, with)
	}
	for _, acronym := range acronyms {
		input = regexp.MustCompile(fmt.Sprintf("\\b%s\\b", acronym)).ReplaceAllString(input, strings.ToUpper(acronym))
	}
	return strings.Title(strings.ReplaceAll(input, "-", " "))
}

func RemapCategory(category string) string {
	if remap, ok := categoryRemap[strings.ToLower(category)]; ok {
		return remap
	}
	return category
}
