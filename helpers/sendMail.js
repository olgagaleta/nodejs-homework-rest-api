const sgMail = require("@sendgrid/mail");
require("dotenv").config();

const { SENDGRID_API_KEY } = process.env;

sgMail.setApiKey(SENDGRID_API_KEY);

const sendMail = async (data) => {
  const mail = { ...data, from: "olga.galeta@meta.ua" };

  sgMail
    .sendMail(mail)
    .then(() => console.log("Mail sent"))
    .catch((e) => console.log(e.message));
};

module.exports = sendMail;
