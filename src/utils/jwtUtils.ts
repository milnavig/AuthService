import jwt, { Secret } from 'jsonwebtoken';
import Token, { IToken } from '../models/Token';

// generates JWT tokens
const generate_jwt = (userId: string) => {
  const SECRET_KEY = process.env.SECRET_KEY as Secret;
  const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY as Secret;

  if (!SECRET_KEY) {
    throw new Error('Secret key is missing');
  }

  if (!REFRESH_SECRET_KEY) {
    throw new Error('Refresh secret key is missing');
  }

  const access_token = jwt.sign({ userId }, SECRET_KEY, {expiresIn: '30m'});
  const refresh_token = jwt.sign({ userId }, REFRESH_SECRET_KEY, {expiresIn: '24h'});
  return { access_token, refresh_token }
}

// save JWT token to DB
async function save_token(userId: string, refreshToken: string, expirationDate: Date) {
  const tokenData: IToken | null = await Token.findOne({ userId });
  if (tokenData) {
    tokenData.refreshToken = refreshToken;
    tokenData.expirationDate = expirationDate;
    return tokenData.save();
  }
  const token = await Token.create({userId, refreshToken, expirationDate});
  return token;
}

// get JWT token from db
async function get_token(refreshToken: string): Promise<IToken | null> {
  const tokenData: IToken | null = await Token.findOne({ refreshToken });

  return tokenData;
}

// delete toke from DB
async function delete_token(refreshToken: string) {
  await Token.deleteOne({refreshToken});
}

export default {
  generate_jwt,
  save_token,
  get_token,
  delete_token
};