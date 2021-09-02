const bcrypt = require("bcryptjs");
const {UserInputError, AuthenticationError} = require("apollo-server");
const jwt = require("jsonwebtoken");
const {Op} = require("sequelize");

const {User} = require("../models");
const {JWT_SECRET} = require("../config/env.json");

module.exports = {
	Query: {
		getUsers: async (parents, args, context) => {
			try {
				let user;
				if (context.req && context.req.headers.authorization) {
					const token = context.req.headers.authorization.split("token ")[1];
					jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
						if (err) {
							throw new AuthenticationError("Unauthenticated ");
						}
						user = decodedToken;
					});
				}

				const users = await User.findAll({
					where: {username: {[Op.ne]: user.username}},
				});
				return users;
			} catch (err) {
				console.log(err);
				throw err;
			}
		},
		login: async (parents, args) => {
			const {username, password} = args;
			let errors = {};

			try {
				if (username.trim() === "")
					errors.username = "username must not be empty";
				if (password.trim() === "")
					errors.password = "password must not be empty";

				if (Object.keys(errors).length > 0) {
					throw new UserInputError("bad input", {errors});
				}

				const user = await User.findOne({
					where: {username},
				});

				if (!user) {
					errors.username = "user not found";
					throw new UserInputError("user not found", {errors});
				}

				const correctPassword = await bcrypt.compare(password, user.password);

				if (!correctPassword) {
					errors.password = "password is incorrect";
					throw new AuthenticationError("password is incorrect", {errors});
				}

				const token = jwt.sign({username}, JWT_SECRET, {
					expiresIn: 60 * 60,
				});

				user.token = token;

				return user;
			} catch (err) {
				console.log(err);
				throw err;
			}
		},
	},
	Mutation: {
		register: async (parent, args) => {
			let {username, email, password, confirmPassword} = args;
			let errors = {};
			try {
				//Validate input data
				if (email.trim() === "") errors.email = "email must not be empty";
				if (username.trim() === "")
					errors.username = "username must not be empty";
				if (password.trim() === "")
					errors.password = "password must not be empty";
				if (confirmPassword.trim() === "")
					errors.confirmPassword = "repeat password must not be empty";

				//Check confirm password
				if (password !== confirmPassword)
					errors.confirmPassword = "passswords must match";

				//Check if username / email exists
				// const userByUsername = await User.findOne({where: {username}});
				// const userByEmail = await User.findOne({where: {email}});

				// if (userByUsername) errors.username = "Username is taken";
				// if (userByEmail) errors.email = "Email is taken";

				if (Object.keys(errors).length > 0) {
					throw errors;
				}
				//Hash password
				password = await bcrypt.hash(password, 6);

				//Create user
				const user = await User.create({
					username,
					email,
					password,
				});

				return user;
			} catch (err) {
				console.log(err);
				if (err.name === "SequelizeUniqueConstraintError") {
					console.log(err.errors);
					err.errors.forEach(
						(e) => (errors[e.path] = `${e.path} is already taken`)
					);
				} else if (err.name === "SequelizeValidationError") {
					err.errors.forEach((e) => (errors[e.path] = e.message));
				}
				throw new UserInputError("Bad input", {errors});
			}
		},
	},
};
