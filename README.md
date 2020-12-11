# SecurityBaseline

This repo helps send reports on MFA checks, Cloudtrail status, S3 bucket status and other checks and sends an email with the list of best practices not being followed on AWS.

This repository includes a Cloudformation Template and a Python script. Zip the python script and upload it to your S3 bucket. 

The Template will deploy a Lambda function which will run every day and sends an email to your subscribed email using AWS SNS.

During the Cloudformation deployment, use the S3 path where you uploaded the Python file and input your email address where you want to receive the alerts.

For testing the lambda immediately, you can invoke it with any test event.
