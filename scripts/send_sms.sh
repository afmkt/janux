#!/bin/sh
# Send a test SMS via Aliyun dysmsapi (requires the aliyun CLI configured
# with your own AccessKey). Replace the placeholders before use.
aliyun dysmsapi send-sms \
    --phone-numbers <your-phone-number> \
    --sign-name '<your-sign-name>' \
    --template-code <your-template-code> \
    --template-param '{"code":"1234"}' \
    --api-version 2017-05-25 \
    --endpoint dysmsapi.aliyuncs.com
