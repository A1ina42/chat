const {gql} = require("apollo-server");

module.exports = gql`
	scalar Date
	type User {
		username: String!
		email: String!
		token: String
		createdAt: Date!
	}
	type Query {
		getUsers: [User]!
		login(username: String!, password: String!): User!
	}
	type Mutation {
		register(
			username: String!
			email: String!
			password: String!
			confirmPassword: String!
		): User!
	}
`;
