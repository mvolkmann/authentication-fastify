import dotenv from 'dotenv';
import mongo from 'mongodb';

const {MongoClient} = mongo;

const collectionMap = {};

// Load environment variables from the .env file into process.env.
dotenv.config();

const url = process.env.MONGO_URL;
export const client = new MongoClient(url, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

export async function connect() {
  try {
    await client.connect();

    // Confirm the connection.
    await client.db('admin').command({ping: 1});

    console.log('connected to MongoDB Atlas database');
  } catch (e) {
    console.error(e);
    await client.close();
  }
}

export function getCollection(name) {
  let collection = collectionMap[name];
  if (!collection) {
    collection = client.db(process.env.MONGO_DB_NAME).collection(name);
    collectionMap[name] = collection;
  }
  return collection;
}
