const express = require("express");
const router = express.Router();
//https://www.google.com/settings/security/lesssecureapps
// mongodb user model
const User = require("./../models/User");
//user verification model
const UserVerification = require("./../models/UserVerification");

//user password reset link
const PasswordReset = require("./../models/PasswordReset");

const UserOTPVerification = require("./../models/UserOTPVerification");

//email handling
const nodemailer = require("nodemailer");

//unique string 
const { v4: uuidv4 } = require("uuid");
//env variables
require("dotenv").config();

//path to access html file
const path = require("path");

// Password handler
const bcrypt = require("bcrypt");
const { connected } = require("process-nextick-args");

//nodemailer stuff
let transporter = nodemailer.createTransport({
  service: 'gmail',
  auth:{
    user: process.env.AUTH_EMAIL,
    pass:process.env.AUTH_PASSWORD
  }
});

//testing success
transporter.verify((error,success) => {
  if(error) console.log(error);
  console.log("Gmail is Ready");
  console.log(success);

});

// Signup
router.post("/signup", (req, res) => {
  let { name, email, password, dateOfBirth } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  dateOfBirth = dateOfBirth.trim();

  if (name == "" || email == "" || password == "" || dateOfBirth == "") {
    res.json({
      status: "FAILED",
      message: "Empty input fields!",
    });
  } else if (!/^[a-zA-Z ]*$/.test(name)) {
    res.json({
      status: "FAILED",
      message: "Invalid name entered",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "FAILED",
      message: "Invalid email entered",
    });
  } else if (!new Date(dateOfBirth).getTime()) {
    res.json({
      status: "FAILED",
      message: "Invalid date of birth entered",
    });
  } else if (password.length < 8) {
    res.json({
      status: "FAILED",
      message: "Password is too short!",
    });
  } else {
    // Checking if user already exists
    User.find({ email })
      .then((result) => {
        if (result.length) {
          // A user already exists
          res.json({
            status: "FAILED",
            message: "User with the provided email already exists",
          });
        } else {
          // Try to create new user

          // password handling
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new User({
                name,
                email,
                password: hashedPassword,
                dateOfBirth,
                verified:false
              });

              newUser
                .save()
                .then((result) => {
                  //send verification email
                  // sendVerificationEmail(result, res);
                  sendOTPVerificationEmail(result,res);
                })
                .catch((err) => {
                  res.json({
                    status: "FAILED",
                    message: "An error occurred while saving user account!",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occurred while hashing password!",
              });
            });
        }
      })
      .catch((err) => {
        console.log(err);
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user!",
        });
      });
  }
});

//OTP section
const sendOTPVerificationEmail = async ({ _id, email }, res) => {
  try {
    const otp = `A-${Math.floor(100000+ Math.random() * 900000)}`;
    //mail oprions
    const mailOptions = {
      from: process.env.AUTH_EMAIL,
      to:email,
      subject:"Verify your Email",
      html:`<p>Enter code <b>${otp}</b> in the app to verify your email address to complete the signup and signin into your account.</p><br>
      <p>This OTP code <b>expires in 1 hour</b></p>`
    }
    const saltRounds = 10;
    const hashedOTP = await bcrypt.hash(otp,saltRounds);
    const newOTPVerification = await new UserOTPVerification({
      userId: _id,
      otp: hashedOTP,
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    });
    //savwe a record in db
    await newOTPVerification.save();
    transporter.sendMail(mailOptions);
    res.json({
      status: "PENDING",
      message: "Verification OTP email sent",
      data:{
        userId: _id,
        email,
      }
    });

  } catch (error) {
    res.json({
      status: "FAILED",
      message: error.message,
    });
  }
}

router.post("/verifyOTP", async (req,res) => {
  try {
    let { userId, otp } = req.body;
    if(!userId || !otp){
      throw new Error("Empty otp details are not allowed");
    }else{
      const UserOTPVerificationRecords = await UserOTPVerification.find({
        userId,
      });
      if(UserOTPVerificationRecords.length <= 0){
        //no record found
        throw new Error(
          "Account record doesn't exist or has been verified already.Please sign up or log in."
          );
      }else{
        const { expiresAt } = UserOTPVerificationRecords[0];
        const hashedOTP = UserOTPVerificationRecords[0].otp;
        if(expiresAt < Date.now()){
          await UserOTPVerification.deleteMany({userId});
          throw new Error("Code has expired. Please request again.");
        }else{
          const validOTP = await bcrypt.compare(otp,hashedOTP);
          if(!validOTP){
            //supplied wrong otp
            throw new Error("Invalid code passed. Check your inbox.");
          }else{
            //success
            await User.updateOne({_id: userId},{verified:true});
            await UserOTPVerification.deleteMany({userId});
            res.json({
              status: "VERIFIED",
              message: "User email verified successfully.",
            });
          }
        }
      }
    }
  } catch (error) {
    res.json({
      status: "FAILED",
      message: error.message
    });
  }
});

router.post("/resendOTPVerificationCode", async(req,res) => {
  try {
    let {userId, email} = req.body;
    if(!userId || !email){
      throw new Error("Empty user details are not allowed.");
    }else{
      //delete existing records and resend
      await UserOTPVerification.deleteMany({userId});
      sendOTPVerificationEmail({_id: userId, email}, res);
    }
  } catch (error) {
    res.json({
      status:"FAILED",
      message: error.message
    });
  }
});

//send verification email
const sendVerificationEmail = ({ _id, email }, res) => {
  //url to be used in verification
  const currentUrl = "http://localhost:3000"
  const uniqueString = uuidv4() + _id;
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to:email,
    subject:"Verify your Email",
    html:`<p>Verify your email address to complete the signup and signin into your account.</p><br><p>This link <b>expires in 6 hours</b></p>
    <p>Click <a href=${currentUrl + "/user/verify/" + _id + "/" + uniqueString}>Here</a> to verify now</p>`
  };

  //hash the uniques string
  const saltRounds = 10;
  bcrypt
  .hash(uniqueString, saltRounds)
  .then((hashedUniqueString) => {
    //set values in user verification table
    const newVerification = new UserVerification({
      userId: _id,
      uniqueString: hashedUniqueString,
      createdAt: Date.now(),
      expiresAt: Date.now() + 21600000,
    });
    newVerification
    .save()
    .then(() => {
      transporter.sendMail(mailOptions)
      .then(() => {
        //email sent successfully and verification record saved
        res.json({
          status: "PENDING",
          message: "Verification email sent",
        });
      })
      .catch((error) => {
        console.log(error);
        res.json({
          status: "FAILED",
          message: "Verification email failed!",
        });
      })
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "FAILED",
        message: "Couldn't save email verification data!",
      });
    });
  })
  .catch(() => {
    res.json({
      status: "FAILED",
      message: "An error occured while hashing email data!",
    });
  })
};

//handle user click link
router.get("/verify/:userId/:uniqueString", (req,res) => {
//LOGIc
  let { userId, uniqueString } = req.params;

  UserVerification
  .find({userId})
  .then((result) => {
    if(result.length > 0){
      //user verification record exists
      const { expiresAt } = result[0];
      const hashedUniqueString = result[0].uniqueString;
      //checking for expiry date
      if(expiresAt < Date.now()){
        //record has expired so we delete it
        UserVerification.deleteOne({ userId })
        .then(result =>{
          User.deleteOne({_id:userId})
          .then(() => {
            let message = "Link has expired. Please signup again!";
            res.redirect(`/user/verified/error=true&message=${message}`);
          })
          .catch((error) => {
            console.log(error);
            let message = "Clearing user with expired unique string failed";
            res.redirect(`/user/verified/error=true&message=${message}`);
          })
        })
        .catch((error) => {
          console.log(error);
          let message = "An Error occurred while clearing expired user verification record";
          res.redirect(`/user/verified/error=true&message=${message}`);
        })
      }else{
        //valid record exists so we validate the user String
        //first compare the hashed unique string
        bcrypt.compare(uniqueString,hashedUniqueString)
        .then(result => {
          if(result){
            //string matches
            User.updateOne({ _id: userId }, {verified: true})
            .then(() => {
              UserVerification.deleteOne({userId})
              .then(() => {
                //email verified successfully
                res.sendFile(path.join(__dirname, "./../views/verified.html"));
              })
              .catch((error) => {
                console.log(error);
                let message = "An Error occurred while finalizing a successful verification";
                res.redirect(`/user/verified/error=true&message=${message}`);
              })
            })
            .catch((error) => {
              let message = "An Error occurred while updating user record to show verified";
              res.redirect(`/user/verified/error=true&message=${message}`);
            })
          }else{
            //existing record but incorrect verification details passed
            let message = "Invalid verification details passed. Check your inbox!";
            res.redirect(`/user/verified/error=true&message=${message}`);
          }
        })
        .catch(error => {
          let message = "An error occurred while comparing unique string";
          res.redirect(`/user/verified/error=true&message=${message}`);
        })
      }
    }else{
      //user verification record does not exist
      let message = "Account record doesn't exist or has been verified already. Please signup or login!";
      res.redirect(`/user/verified/error=true&message=${message}`);
    }
  })
  .catch((error) => {
    console.log(error);
    let message = "An Error occurred while checking for existing user verification record";
    res.redirect(`/user/verified/error=true&message=${message}`);
  })

});

router.get("/verified", (req,res) => {
  res.sendFile(path.join(__dirname, "./../views/verified.html"));

});


// Signin
router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "FAILED",
      message: "Empty credentials supplied",
    });
  } else {
    // Check if user exist
    User.find({ email })
      .then((data) => {
        if (data.length) {
          // User exists

          //check if user is verified
          if(!data[0].verified){
            res.json({
              status: "FAILED",
              message: "User Email hasn't been verified yet. Check your inbox!",
            });
          }else{
            const hashedPassword = data[0].password;
            bcrypt
              .compare(password, hashedPassword)
              .then((result) => {
                if (result) {
                  // Password match
                  res.json({
                    status: "SUCCESS",
                    message: "Signin successful",
                    data: data,
                  });
                } else {
                  res.json({
                    status: "FAILED",
                    message: "Invalid password entered!",
                  });
                }
              })
              .catch((err) => {
                res.json({
                  status: "FAILED",
                  message: "An error occurred while comparing passwords",
                });
              });
          }
         
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid credentials entered!",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user",
        });
      });
  }
});

//password reset stuff
router.post("/requestPasswordReset", (req,res) => {
  const { email,redirectUrl } = req.body;

  //check if email exists
  User.find({email})
  .then((data) => {
    //user exists
    if(data.length){
    
      //check if user is verified
      if(!data[0].verified){
        res.json({
          status: "FAILED",
          message: "Email hasn't been verified yet. Check your inbox!",
        });
      }else{
          //proceed with email to reset password
          sendResetEmail(data[0], redirectUrl, res);
      }
    }else{
      res.json({
        status: "FAILED",
        message: "No account with the supplied email exists.",
      });
    }
  })
  .catch(error => {
    console.log(error);
    res.json({
      status: "FAILED",
      message: "An error occurred while checking for existing user email",
    });
  });
});


//send password reset email
const sendResetEmail = ({_id, email},redirectUrl, res) => {
    const resetString = uuidv4() + _id;

    //we clear the existing records
    PasswordReset.deleteMany({ userId: _id })
    .then(result => {
      //record deleted successfully,we send the email
      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to:email,
        subject:"Password Reset",
        html:`<p>We heard that you forgot your password.</p><p>Don't worry, use the link below to reset it.😇</p><br>
        <p>This link <b>expires in 60 minutes</b></p>
        <p>Click <a href=${redirectUrl + "/" + _id + "/" + resetString}>Here</a> to reset now</p>`
      };

      //hash the reset string
      const saltRounds = 10;
      bcrypt
      .hash(resetString, saltRounds)
      .then(hashedResetString => {
        //create values in password reset collection
        const newPasswordReset = new PasswordReset({
          userId: _id,
          resetString: hashedResetString,
          createdAt: Date.now(),
          expiresAt: Date.now() + 3600000
        });
        newPasswordReset
        .save()
        .then(() => {
          transporter
          .sendMail(mailOptions)
          .then(() => {
            //reset email sent and password resent record saved
            res.json({
              status: "PENDING",
              message: "Password reset email sent!",
            });
          })
          .catch(error => {
            console.log(error);
            res.json({
              status: "FAILED",
              message: "Password reset email failed!",
            });
          })

        })
        .catch(error => {
          console.log(error);
          res.json({
            status: "FAILED",
            message: "Coudn't save password reset data!",
          });
        });

      })
      .catch(error => {
        console.log(error);
        res.json({
          status: "FAILED",
          message: "An error occurred while hashing the password reset data!",
        });
      });
    })
    .catch(error =>{
      console.log(error);
      res.json({
        status: "FAILED",
        message: "Clearing existing password reset records failed!",
      });
    });
}

//Actual reset the password
router.post("/resetPassword", (req,res) => {
  let { userId,resetString, newPassword } = req.body;
  PasswordReset.find({userId})
  .then(result => {
    if (result.length> 0){
        //password reset record exists we proceed
        const {expiresAt} = result[0];
        const hashedResetString = result[0].resetString;
        //checking for expiry date
        if(expiresAt < Date.now()){
          PasswordReset.deleteOne({userId})
          .then(() => {
            res.json({
              status: "FAILED",
              message: "Password reset has expired. Please request again.",
            });
          })
          .catch(error => {
            console.log(error);
            res.json({
              status: "FAILED",
              message: "Clearing password reset record failed!",
            });
          });
        }else{
          //valid reset record exists so we validate the reset string
          //first compare the hashed reset string
          bcrypt.compare(resetString, hashedResetString)
          .then((result) => {
              if(result){
                //hash the new password 
                //deposit it into database
                const saltRounds = 10;
                bcrypt.hash(newPassword, saltRounds)
                .then(hashedNewPassword => {
                  //update user password
                  User.updateOne({_id: userId},{password: hashedNewPassword})
                  .then(()=>{
                    //update complete.
                    //now clear the password reset link from database
                    PasswordReset.deleteOne({userId})
                    .then(() => {
                      //both user record and reset record updated
                      res.json({
                        status: "SUCCESS",
                        message: "Password has been reset successfully!",
                      });
                    })
                    .catch(error => {
                      console.log(error);
                      res.json({
                        status: "FAILED",
                        message: "An error occurred while finalizing password reset!",
                      });
                    });
                  })
                  .catch(error => {
                    console.log(error);
                    res.json({
                      status: "FAILED",
                      message: "Updating user password failed!",
                    });
                  })
                })
                .catch(error => {
                  console.log(error);
                  res.json({
                    status: "FAILED",
                    message: "An error occurred while hashing new password!",
                  });
                });
              }else{
                //existing record but incorrect reset string passed
                res.json({
                  status: "FAILED",
                  message: "Invalid password reset details passed!",
                });
              }
          })
          .catch(error => {
            res.json({
              status: "FAILED",
              message: "Comparing password reset strings failed!",
            });
          });
        }

    }else{
      //password reset record doesn't exist
      res.json({
        status: "FAILED",
        message: "Password reset request not found",
      });
    }
  })
  .catch(error =>{
    console.log(error);
    res.json({
      status: "FAILED",
      message: "Checking for existing password reset record failed!",
    });
  });
});
module.exports = router;

