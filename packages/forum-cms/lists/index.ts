import User from './user'
import Category from './category'
import Comment from './comment'
import Member from './member'
import Tag from './tag'
import Image from './image'
import Post from './Post'
import Reaction from './Reaction'

export const listDefinition = {
  User,
  Category,
  Comment,
  Tag,
  Member,
  Post,
  Reaction,
  Photo: Image,
}
