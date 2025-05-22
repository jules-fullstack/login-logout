const nodemailer = require("nodemailer");

const createTransporter = () => {
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
    debug: process.env.NODE_ENV !== "production",
  });
};

const sendVerificationEmail = async (name, email, token) => {
  const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
  const verifyUrl = `${clientUrl}/verify-email/${token}`;

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Verify Your Email</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          margin: 0;
          padding: 0;
          background-color: #f9f9f9;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background-color: #3498db;
          padding: 30px;
          color: white;
          text-align: center;
          border-radius: 8px 8px 0 0;
        }
        .content {
          background-color: white;
          padding: 40px 30px;
          border-radius: 0 0 8px 8px;
          box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }
        .button {
          display: inline-block;
          background-color: #3498db;
          color: white;
          text-decoration: none;
          padding: 14px 30px;
          border-radius: 4px;
          margin: 20px 0;
          font-weight: bold;
          text-align: center;
          transition: background-color 0.3s;
        }
        .button:hover {
          background-color: #2980b9;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          color: #666;
          font-size: 12px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Verify Your Email</h1>
        </div>
        <div class="content">
          <p>Hello ${name},</p>
          <p>Thank you for signing up! To complete your registration, please verify your email address by clicking the button below:</p>
          
          <div style="text-align: center;">
            <a href="${verifyUrl}" class="button">Verify Email</a>
          </div>
          
          <p>This link will expire in 24 hours for security reasons.</p>
          
          <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
          <p>${verifyUrl}</p>
          
          <p>If you didn't create an account, you can safely ignore this email.</p>
          
          <p>Best regards,<br>The Team</p>
        </div>
        <div class="footer">
          <p>&copy; ${new Date().getFullYear()} Your Company. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  const mailOptions = {
    from: `"Account Verification" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Verify Your Email Address",
    html: htmlContent,
  };

  try {
    const transporter = createTransporter();
    const info = await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error("Error sending verification email:", error);
    return false;
  }
};

const sendWelcomeEmail = async (name, email) => {
  // Default client URL if not set in environment
  const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
  const loginUrl = `${clientUrl}/login`;

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to Our Platform</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          margin: 0;
          padding: 0;
          background-color: #f9f9f9;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background-color: #3498db;
          padding: 30px;
          color: white;
          text-align: center;
          border-radius: 8px 8px 0 0;
        }
        .content {
          background-color: white;
          padding: 40px 30px;
          border-radius: 0 0 8px 8px;
          box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }
        .welcome-image {
          text-align: center;
          margin: 20px 0;
        }
        .welcome-image img {
          max-width: 200px;
        }
        .button {
          display: inline-block;
          background-color: #3498db;
          color: white;
          text-decoration: none;
          padding: 14px 30px;
          border-radius: 4px;
          margin: 20px 0;
          font-weight: bold;
          text-align: center;
          transition: background-color 0.3s;
        }
        .button:hover {
          background-color: #2980b9;
        }
        .features {
          margin: 30px 0;
          display: flex;
          justify-content: space-between;
          flex-wrap: wrap;
        }
        .feature {
          flex-basis: 30%;
          text-align: center;
          margin-bottom: 20px;
        }
        .feature-icon {
          font-size: 24px;
          margin-bottom: 10px;
          color: #3498db;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          color: #666;
          font-size: 12px;
        }
        .social-links {
          margin: 15px 0;
        }
        .social-links a {
          display: inline-block;
          margin: 0 10px;
          color: #3498db;
          text-decoration: none;
        }
        @media only screen and (max-width: 600px) {
          .feature {
            flex-basis: 100%;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Welcome to Our Platform!</h1>
        </div>
        <div class="content">
          <p>Hello ${name},</p>
          <p>Thank you for joining our platform! We're excited to have you as part of our community.</p>
          
          <div class="welcome-image">
            <!-- Replace with your actual logo or welcome image -->
            <div style="font-size: 60px; color: #3498db;">✨</div>
          </div>
          
          <p>Your account has been successfully created and is ready to use. Here's what you can do next:</p>
          
          <div class="features">
            <div class="feature">
              <div class="feature-icon">👤</div>
              <h3>Complete Profile</h3>
              <p>Add more information to your profile</p>
            </div>
            <div class="feature">
              <div class="feature-icon">🔐</div>
              <h3>Secure Account</h3>
              <p>Set up additional security</p>
            </div>
            <div class="feature">
              <div class="feature-icon">🚀</div>
              <h3>Explore Features</h3>
              <p>Discover what you can do</p>
            </div>
          </div>
          
          <div style="text-align: center;">
            <a href="${loginUrl}" class="button">Get Started</a>
          </div>
          
          <p>If you have any questions or need assistance, feel free to reply to this email or contact our support team.</p>
          
          <p>Best regards,<br>The Team</p>
          
          <div class="footer">
            <div class="social-links">
              <a href="#">Facebook</a>
              <a href="#">Twitter</a>
              <a href="#">Instagram</a>
            </div>
            <p>&copy; ${new Date().getFullYear()} Your Company. All rights reserved.</p>
            <p>123 Example Street, City, Country</p>
          </div>
        </div>
      </div>
    </body>
    </html>
  `;

  const mailOptions = {
    from: `"Welcome" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Welcome to Our Platform!",
    html: htmlContent,
  };

  try {
    const transporter = createTransporter();
    const info = await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error("Error sending welcome email:", error);
    return false;
  }
};

const sendPasswordResetEmail = async (email, token) => {
  const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
  const resetUrl = `${clientUrl}/reset-password/${token}`;

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

  const mailOptions = {
    from: `"Password Reset" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Reset Your Password",
    html: htmlContent,
  };
  try {
    const transporter = createTransporter();
    const info = await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error("Error sending password reset email");
    return false;
  }
};

const sendOtpEmail = async (email, otp) => {
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Your Login Verification Code</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: #333;
          margin: 0;
          padding: 0;
          background-color: #f9f9f9;
        }
        .container {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background-color: #3498db;
          padding: 30px;
          color: white;
          text-align: center;
          border-radius: 8px 8px 0 0;
        }
        .content {
          background-color: white;
          padding: 40px 30px;
          border-radius: 0 0 8px 8px;
          box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }
        .code-container {
          margin: 20px 0;
          text-align: center;
        }
        .code {
          font-size: 32px;
          font-weight: bold;
          letter-spacing: 8px;
          color: #333;
          padding: 15px 20px;
          background-color: #f0f0f0;
          border-radius: 6px;
          display: inline-block;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #eee;
          color: #666;
          font-size: 12px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Login Verification</h1>
        </div>
        <div class="content">
          <p>Hello,</p>
          <p>We've received a login attempt for your account. To complete the login process, please enter the following verification code:</p>
          
          <div class="code-container">
            <div class="code">${otp}</div>
          </div>
          
          <p>This code will expire in 10 minutes for security reasons.</p>
          
          <p>If you didn't try to log in, please secure your account by changing your password immediately.</p>
          
          <p>Best regards,<br>The Team</p>
        </div>
        <div class="footer">
          <p>&copy; ${new Date().getFullYear()} Your Company. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;

  const mailOptions = {
    from: `"Account Security" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "Your Login Verification Code",
    html: htmlContent,
  };

  try {
    const transporter = createTransporter();
    const info = await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error("Error sending OTP email:", error);
    return false;
  }
};


module.exports = {
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendVerificationEmail,
  sendOtpEmail
};
