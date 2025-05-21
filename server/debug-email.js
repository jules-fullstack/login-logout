require("dotenv").config();
const nodemailer = require("nodemailer");

async function testReset() {
  try {
    // Print all environment variables
    console.log("Environment variables:");
    console.log("MAIL_HOST:", process.env.MAIL_HOST);
    console.log("MAIL_PORT:", process.env.MAIL_PORT);
    console.log(
      "MAIL_USER:",
      process.env.MAIL_USER ? "Set but hidden" : "Not set"
    );
    console.log(
      "MAIL_PASS:",
      process.env.MAIL_PASS ? "Set but hidden" : "Not set"
    );
    console.log("CLIENT_URL:", process.env.CLIENT_URL);

    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: parseInt(process.env.MAIL_PORT),
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
      debug: true,
      logger: true,
    });

    // Generate a test token
    const resetToken = "test-token-123";
    const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
    const resetUrl = `${clientUrl}/reset-password/${resetToken}`;

    console.log("Reset URL:", resetUrl);

    // Simplified HTML template
    const htmlContent = `
      <div>
        <h1>Reset Your Password</h1>
        <p>Click the link below to reset your password:</p>
        <a href="${resetUrl}">Reset Password</a>
      </div>
    `;

    // Send email
    const info = await transporter.sendMail({
      from: '"Password Reset" <reset@example.com>',
      to: "deonnlansangan@gmail.com",
      subject: "Password Reset Test",
      html: htmlContent,
    });

    console.log("Email sent:", info.messageId);
  } catch (error) {
    console.error("Error in test:", error);
    console.error("Error stack:", error.stack);
  }
}

// Run the test
testReset();
