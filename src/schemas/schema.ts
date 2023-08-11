export const schema = `#graphql
  type Message {
    message: String!
  }

  type TokenData {
    access_token: String!
    refresh_token: String!
  }

  type Query {
    logout: Message!
    refresh: TokenData!
  }

  input UserInput {
    email: String!
    password: String!
  }

  type CodeData {
    userId: String!
    qrcodeUrl: String!
  }

  input CodeInput {
    userId: String!
    otpAuthUrl: String!
  }

  input UpdateInput {
    old_password: String!
    new_password: String!
  }

  type Mutation {
    register(input: UserInput!): Message!
    enable_2fa(input: UserInput!): CodeData!
    login_2fa(input: CodeInput!): TokenData!
    update(input: UpdateInput!): Message!
  }
`;