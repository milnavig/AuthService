import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import bodyParser from 'body-parser';
import { ApolloServer } from '@apollo/server';
import { expressMiddleware } from '@apollo/server/express4';
import cookieParser from 'cookie-parser';
import userRoutes from './routes/userRoutes';
import errorHandler from './middleware/errorHandlerMiddleware';
import { connectToDatabase } from './db';
import { schema } from './schemas/schema';
import { resolvers } from './resolver';
import { context } from './context';
import IContext from './interfaces/IContext';

dotenv.config();

const PORT = process.env.PORT || 5000;

connectToDatabase(); // Call the function to connect to the MongoDB database

const app = express();

app.use(cors({
  credentials: true,
  origin: process.env.CLIENT_URL
}));

app.use(express.json());

// need cookieParser middleware before we can do anything with cookies
app.use(cookieParser());

// mount the authRoutes
app.use('/api/user', userRoutes);

// function which starts Express server
const startExpressServer = () => {
  try {
    app.listen(PORT, () => console.log('The server was launched!'));
  } catch(err) {
    console.log(err);
  }
}

// function which starts ApolloServer
const startApolloServer = async () => {
  const server = new ApolloServer<IContext>({
    typeDefs: schema,
    resolvers,
  });
  // Note you must call `start()` on the `ApolloServer`
  // instance before passing the instance to `expressMiddleware`
  await server.start();
  
  app.use(
    '/graphql', 
    cors<cors.CorsRequest>(), 
    bodyParser.json(), 
    expressMiddleware(
      server, 
      { context }
    )
  );

  app.use(errorHandler); // middleware for error handling

  startExpressServer();
}

startApolloServer();