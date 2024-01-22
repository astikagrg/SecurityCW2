import bcrypt from 'bcryptjs'

const users = [
  {
    name: 'Admin User',
    email: 'admin@example.com',
    password: bcrypt.hashSync('Ecom@123', 10),
    isAdmin: true,
    lastPasswordChange: Date.now()
  },
  {
    name: 'John Doe',
    email: 'john@example.com',
    password: bcrypt.hashSync('Ecom@123', 10),
    lastPasswordChange: Date.now()
  },
  {
    name: 'Jane Doe',
    email: 'jane@example.com',
    password: bcrypt.hashSync('Ecom@123', 10),
    lastPasswordChange: Date.now()
  },
]

export default users
