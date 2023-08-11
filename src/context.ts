import jwt, { Secret, JwtPayload } from 'jsonwebtoken';
import Token, { IToken } from './models/Token';

// creates context for Apollo Server
// check if the user is logged in. If so, appends to Request info about user
export const context = async ({ req, res }: any) => {
  try {
    const SECRET_KEY = process.env.SECRET_KEY as Secret; // secret key for JWT access token

    const token = req.headers?.authorization?.split(' ')[1] || ''; // Bearer 1234

    const decoded_token = jwt.verify(token, SECRET_KEY) as JwtPayload;

    // search if user has refresh toke in the database
    const refreshToken: IToken | null = await Token.findOne({ userId: decoded_token.userId });

    if (!refreshToken || !decoded_token) {
      throw new Error('User not authorized!');
    }

    req.user = decoded_token;

    return { req, res };
  } catch(error) {
    return { req, res };
  }
}