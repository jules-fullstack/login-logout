require("dotenv").config();
const nodemailer = require("nodemailer");

async function testGmailEmail() {
  try {
    // Print current environment setup
    console.log("Environment variables:");
    console.log(
      "GMAIL_USER:",
      process.env.GMAIL_USER ? "Set but hidden" : "Not set"
    );
    console.log(
      "GMAIL_APP_PASSWORD:",
      process.env.GMAIL_APP_PASSWORD ? "Set but hidden" : "Not set"
    );
    console.log("CLIENT_URL:", process.env.CLIENT_URL);

    // Create transporter for Gmail
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD,
      },
      debug: true,
    });

    // Create a simple test email
    const mailOptions = {
      from: `"Password Reset Test" <${process.env.GMAIL_USER}>`,
      to: process.env.GMAIL_USER, // Send to yourself for testing
      subject: "Test Email from Node.js App",
      text: "This is a test email from your Node.js application.",
      html: "<b>This is a test email from your Node.js application.</b><p>If you received this, your Gmail configuration is working!</p>",
    };

    // Send the email
    console.log("Attempting to send test email...");
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent successfully:", info.messageId);
  } catch (error) {
    console.error("Error sending test email:", error);
    console.error("Stack trace:", error.stack);
  }
}

// Run the test
testGmailEmail().catch(console.error);
