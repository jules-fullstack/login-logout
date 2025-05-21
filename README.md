# Authentication System

A complete authentication system with login, signup, and password reset functionality.

## Features

- User registration and login
- JWT-based authentication
- Password reset via email
- Protected routes
- Modern UI with responsive design

## Tech Stack

### Frontend

- React.js
- React Router
- Vite
- Axios

### Backend

- Express.js
- MongoDB (with Mongoose)
- JWT for authentication
- Nodemailer (Gmail) for emails

## Setup Instructions

### Prerequisites

- Node.js and npm
- MongoDB database
- Gmail account (for password reset emails)

### Backend Setup

1. Navigate to the server directory:

   ```bash
   cd server
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Create a `.env` file with the following variables:

   ```
   PORT=5000
   MONGO_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
   GMAIL_USER=your_gmail_address
   GMAIL_APP_PASSWORD=your_gmail_app_password
   CLIENT_URL=http://localhost:5173
   ```

4. Start the server:
   ```bash
   npm start
   ```

### Frontend Setup

1. Navigate to the client directory:

   ```bash
   cd client
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

## Gmail Setup for Password Reset

To use Gmail for password reset emails:

1. Create a Gmail account or use an existing one
2. Enable 2-Step Verification in your Google Account security settings
3. Generate an App Password (Google Account → Security → App Passwords)
4. Use this App Password in your `.env` file
