require("dotenv").config();
const nodemailer = require("nodemailer");

async function testEmail() {
  // Create a test transporter
  const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
    debug: true, // Show debug output
    logger: true, // Log information
  });

  console.log("SMTP Configuration:", {
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
      user: process.env.MAIL_USER ? "Set but hidden" : "Not set",
      pass: process.env.MAIL_PASS ? "Set but hidden" : "Not set",
    },
  });

  // Send test email
  try {
    const info = await transporter.sendMail({
      from: '"Test" <test@example.com>',
      to: "recipient@example.com",
      subject: "Test Email",
      text: "This is a test email from Nodemailer",
      html: "<b>This is a test email from Nodemailer</b>",
    });

    console.log("Message sent: %s", info.messageId);
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
  } catch (error) {
    console.error("Error sending email:", error);
  }
}

testEmail().catch(console.error);
