import smtplib
import ssl
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import EMAIL_HOST, EMAIL_PORT, EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_FROM, RECAPTCHA_SECRET_KEY, logger


def send_email(recipient_email: str, subject: str, body: str) -> bool:
    """
    Send an email using Gmail SMTP.
    
    Args:
        recipient_email (str): The recipient's email address
        subject (str): The email subject
        body (str): The email body content
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    # Log email configuration for debugging (mask password for security)
    logger.info(f"Attempting to send email:")
    logger.info(f"  HOST: {EMAIL_HOST}")
    logger.info(f"  PORT: {EMAIL_PORT}")
    logger.info(f"  USERNAME: {EMAIL_USERNAME}")
    logger.info(f"  FROM: {EMAIL_FROM}")
    logger.info(f"  TO: {recipient_email}")
    logger.info(f"  SUBJECT: {subject}")
    logger.info(f"  EMAIL_PASSWORD is {'set' if EMAIL_PASSWORD else 'NOT SET'}")
    
    try:
        # Create a multipart message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = EMAIL_FROM
        message["To"] = recipient_email

        # Create the HTML part of the email
        html_part = MIMEText(body, "html")
        message.attach(html_part)

        # Create secure connection with server and send email
        context = ssl.create_default_context()
        
        # Connect to Gmail SMTP server
        logger.info(f"Connecting to SMTP server: {EMAIL_HOST}:{EMAIL_PORT}")
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            logger.info("Starting TLS connection")
            server.starttls(context=context)
            logger.info("TLS connection established")
            logger.info("Attempting to log in to SMTP server")
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            logger.info("Successfully logged in to SMTP server")
            logger.info("Sending email")
            server.sendmail(EMAIL_FROM, recipient_email, message.as_string())
            logger.info("Email sent successfully")
        
        logger.info(f"Email sent successfully to {recipient_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email}")
        logger.error(f"Error type: {type(e).__name__}")
        logger.error(f"Error message: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def send_verification_email(recipient_email: str, verification_url: str, verification_code: str) -> bool:
    """
    Send email verification email with verification link and code.
    
    Args:
        recipient_email (str): The recipient's email address
        verification_url (str): The URL for email verification
        verification_code (str): The 6-digit verification code
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    logger.info(f"Preparing verification email for {recipient_email}")
    subject = "Verify Your Email Address"
    
    # HTML email body
    html_body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #1976d2, #2196f3); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1>Email Verification</h1>
          </div>
          <div style="background: #f5f7fa; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
            <h2 style="color: #1976d2;">Welcome to SCMXpertLite!</h2>
            <p>Thank you for registering with us. To complete your registration, please verify your email address.</p>
            
            <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p>Click the button below to verify your email address:</p>
              <div style="text-align: center; margin: 20px 0;">
                <a href="{verification_url}" 
                   style="background: #1976d2; color: white; padding: 12px 25px; text-decoration: none; 
                          border-radius: 5px; font-weight: bold; display: inline-block;">
                  Verify Email Address
                </a>
              </div>
              <p style="font-size: 14px; color: #666;">
                Or copy and paste this link in your browser:<br>
                <span style="word-break: break-all; color: #1976d2;">{verification_url}</span>
              </p>
            </div>
            
            <p>If you didn't create an account with us, please ignore this email.</p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #757575; font-size: 12px;">
              <p>This is an automated message, please do not reply to this email.</p>
              <p>© 2025 SCMXpertLite. All rights reserved.</p>
            </div>
          </div>
        </div>
      </body>
    </html>
    """
    
    logger.info(f"Calling send_email for verification email")
    result = send_email(recipient_email, subject, html_body)
    logger.info(f"send_email returned: {result}")
    return result


def send_password_reset_email(recipient_email: str, reset_url: str) -> bool:
    """
    Send password reset email with reset link.
    
    Args:
        recipient_email (str): The recipient's email address
        reset_url (str): The URL for password reset
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    logger.info(f"Preparing password reset email for {recipient_email}")
    subject = "Password Reset Request"
    
    # HTML email body
    html_body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #1976d2, #2196f3); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1>Password Reset</h1>
          </div>
          <div style="background: #f5f7fa; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
            <h2 style="color: #1976d2;">Reset Your Password</h2>
            <p>We received a request to reset your password for your SCMXpertLite account.</p>
            
            <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p>Click the button below to reset your password:</p>
              <div style="text-align: center; margin: 20px 0;">
                <a href="{reset_url}" 
                   style="background: #1976d2; color: white; padding: 12px 25px; text-decoration: none; 
                          border-radius: 5px; font-weight: bold; display: inline-block;">
                  Reset Password
                </a>
              </div>
              <p style="font-size: 14px; color: #666;">
                Or copy and paste this link in your browser:<br>
                <span style="word-break: break-all; color: #1976d2;">{reset_url}</span>
              </p>
            </div>
            
            <p><strong>Note:</strong> This link will expire in 1 hour for security reasons.</p>
            <p>If you didn't request a password reset, you can safely ignore this email.</p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #757575; font-size: 12px;">
              <p>This is an automated message, please do not reply to this email.</p>
              <p>© 2025 SCMXpertLite. All rights reserved.</p>
            </div>
          </div>
        </div>
      </body>
    </html>
    """
    
    logger.info(f"Calling send_email for password reset email")
    result = send_email(recipient_email, subject, html_body)
    logger.info(f"send_email returned: {result}")
    return result


def send_admin_request_approved_email(recipient_email: str) -> bool:
    """
    Send email notification when admin request is approved.
    
    Args:
        recipient_email (str): The recipient's email address
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    logger.info(f"Preparing admin request approved email for {recipient_email}")
    subject = "Admin Access Request Approved"
    
    # HTML email body
    html_body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #4caf50, #388e3c); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1>Admin Access Granted</h1>
          </div>
          <div style="background: #f5f7fa; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
            <h2 style="color: #388e3c;">Congratulations!</h2>
            <p>Your request for admin privileges has been approved.</p>
            
            <div style="background: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p>You now have admin access to SCMXpertLite and can login as an administrator.</p>
              <p>Thank you for your interest in helping manage our platform.</p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="http://localhost:8000/login" 
                 style="background: #4caf50; color: white; padding: 12px 25px; text-decoration: none; 
                        border-radius: 5px; font-weight: bold; display: inline-block;">
                Login as Admin
              </a>
            </div>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #757575; font-size: 12px;">
              <p>This is an automated message, please do not reply to this email.</p>
              <p>© 2025 SCMXpertLite. All rights reserved.</p>
            </div>
          </div>
        </div>
      </body>
    </html>
    """
    
    logger.info(f"Calling send_email for admin request approved email")
    result = send_email(recipient_email, subject, html_body)
    logger.info(f"send_email returned: {result}")
    return result


def send_admin_request_rejected_email(recipient_email: str) -> bool:
    """
    Send email notification when admin request is rejected.
    
    Args:
        recipient_email (str): The recipient's email address
    
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    logger.info(f"Preparing admin request rejected email for {recipient_email}")
    subject = "Admin Access Request Status"
    
    # HTML email body
    html_body = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #f44336, #d32f2f); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1>Admin Access Request</h1>
          </div>
          <div style="background: #f5f7fa; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
            <h2 style="color: #d32f2f;">Request Update</h2>
            <p>Thank you for your interest in becoming an administrator.</p>
            
            <div style="background: #ffebee; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p>We regret to inform you that your request for admin privileges has not been approved at this time.</p>
              <p>Better luck next time.</p>
            </div>
            
            <p>If you have any questions or would like to reapply in the future, please don't hesitate to reach out to our support team.</p>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #757575; font-size: 12px;">
              <p>Thank you for your understanding.</p>
              <p>This is an automated message, please do not reply to this email.</p>
              <p>© 2025 SCMXpertLite. All rights reserved.</p>
            </div>
          </div>
        </div>
      </body>
    </html>
    """
    
    logger.info(f"Calling send_email for admin request rejected email")
    result = send_email(recipient_email, subject, html_body)
    logger.info(f"send_email returned: {result}")
    return result


def verify_recaptcha(recaptcha_response: str) -> bool:
    """
    Verify reCAPTCHA response with Google's reCAPTCHA API.
    
    Args:
        recaptcha_response (str): The reCAPTCHA response token from the client
        
    Returns:
        bool: True if reCAPTCHA verification is successful, False otherwise
    """
    if not recaptcha_response:
        logger.warning("reCAPTCHA verification failed: No response token provided")
        return False
    
    if not RECAPTCHA_SECRET_KEY:
        logger.error("reCAPTCHA verification failed: RECAPTCHA_SECRET_KEY not configured")
        return False
    
    try:
        # Prepare the verification request
        verification_data = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        
        # Send verification request to Google
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=verification_data)
        response_json = response.json()
        
        # Check if verification was successful
        if response_json.get('success'):
            logger.info("reCAPTCHA verification successful")
            return True
        else:
            logger.warning(f"reCAPTCHA verification failed: {response_json.get('error-codes', 'Unknown error')}")
            return False
            
    except Exception as e:
        logger.error(f"reCAPTCHA verification error: {str(e)}")
        return False
