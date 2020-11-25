const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;

const client = require('twilio')(accountSid, authToken);

const sendSms = async (options) => {
  const message = {
    body: options.body,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: options.toPhoneNumber,
  };

  const response = await client.messages.create(message);
};

module.exports = sendSms;

//Example for sending SMS
//-----------------------
//const sendSms = require('../utils/sendSms');

//const body = 'Hello World!';
//const toPhoneNumber = '+12047955857';
//sendSms({ body, toPhoneNumber });
