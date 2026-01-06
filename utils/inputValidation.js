exports.validateUsr = ({ name, email, password }) => {
  if (!name || !email || !password) {
    throw new Error("All fields are required");
  }
};
