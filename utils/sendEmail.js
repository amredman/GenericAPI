const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendEmail = async (options) => {
  // Create message
  const message = {
    from: `${process.env.FROM_NAME} <${process.env.FROM_EMAIL}>`,
    to: options.email,
    subject: options.subject,
    text: options.text,
    html: options.html,
  };

  // Send Email
  await sgMail.send(message);

  //Log output
  console.log('Message sent');
};

module.exports = sendEmail;
