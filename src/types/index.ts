export interface User {
  _id?: string;
  name?: string;
  email?: string;
  avatar?: string;
  role?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface Comment {
  _id?: string;
  content: string;
  ideaId?: string;
  userId?: string;
  user?: User;
  createdAt?: string;
  updatedAt?: string;
}

export interface Idea {
  _id?: string;
  title: string;
  description: string;
  category?: string;
  tags?: string[];
  author?: User;
  authorId?: string;
  comments?: Comment[];
  createdAt?: string;
  updatedAt?: string;
}

export interface AuthPayload {
  email: string;
  password?: string;
  name?: string;
}
