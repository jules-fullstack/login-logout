const nodemailer = require("nodemailer");

// Create reusable transporter
const createTransporter = () => {
  console.log("Creating email transporter with Gmail");

  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD, // App password, not regular Gmail password
    },
    debug: process.env.NODE_ENV !== "production", // Only enable debug in non-production
  });
};

// Send password reset email
const sendPasswordResetEmail = async (email, token) => {
  // Default client URL if not set in environment
  const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
  const resetUrl = `${clientUrl}/reset-password/${token}`;

  // Create HTML email template
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Your Password</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          margin: 0;
          padding: 0;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
          background-color: #f8f9fa;
        }
        .header {
          background-color: #4361ee;
          padding: 20px;
          color: white;
          text-align: center;
          border-radius: 8px 8px 0 0;
        }
        .content {
          background-color: white;
          padding: 30px;
          border-radius: 0 0 8px 8px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .button {
          display: inline-block;
          background-color: #4361ee;
          color: white;
          text-decoration: none;
          padding: 12px 24px;
          border-radius: 4px;
          margin: 20px 0;
          font-weight: bold;
          text-align: center;
        }
        .footer {
          text-align: center;
          margin-top: 20px;
          font-size: 12px;
          color: #666;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Reset Your Password</h1>
        </div>
        <div class="content">
          <p>Hello,</p>
          <p>We received a request to reset your password. Click the button below to create a new password:</p>
          <div style="text-align: center;">
            <a href="${resetUrl}" class="button">Reset Password</a>
          </div>
          <p>If you didn't request a password reset, you can safely ignore this email.</p>
          <p>This link will expire in 1 hour for security reasons.</p>
          <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
          <p>${resetUrl}</p>
        </div>
        <div class="footer">
          <p>&copy; ${new Date().getFullYear()} Your Application. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;
  // Setup email options
  const mailOptions = {
    from: `"Password Reset" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Reset Your Password",
    html: htmlContent,
  }; // Send email
  try {
    console.log("Attempting to send password reset email to:", email);

    const transporter = createTransporter();

    const info = await transporter.sendMail(mailOptions);
    console.log("Password reset email sent:", info.messageId);
    return true;
  } catch (error) {
    console.error("Error sending password reset email:", error);
    console.error("Error stack:", error.stack);
    return false;
  }
};

module.exports = { sendPasswordResetEmail };
