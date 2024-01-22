import asyncHandler from 'express-async-handler'
import generateToken from '../utils/generateToken.js'
import User from '../models/userModel.js'

// @desc    Auth user & get token
// @route   POST /api/users/login
// @access  Public
// Create an object to keep track of login attempts and lock status
const loginAttempts = {};

const maxLoginAttempts = 3; // Maximum allowed login attempts

const authUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Check if the user's account is locked
  if (loginAttempts[email] && loginAttempts[email].attempts >= maxLoginAttempts) {
    const currentTime = new Date().getTime();
    const lockDuration = 60000; // 1 minute in milliseconds

    if (currentTime - loginAttempts[email].lastAttempt < lockDuration) {
      const remainingTime = Math.ceil((lockDuration - (currentTime - loginAttempts[email].lastAttempt)) / 1000);
      return res.status(401).json({ message: `Account locked. Try again in ${remainingTime} seconds.` });
    } else {
      // Unlock the account
      delete loginAttempts[email];
    }
  }

  const user = await User.findOne({ email });

  if (user) {
    if (await user.matchPassword(password)) {
      // Successful login, reset login attempts

      // Password change logic
      const passwordChangeInterval = 5 * 60 * 60 * 1000; // 5 hours in milliseconds

      if (user.lastPasswordChange && Date.now() - user.lastPasswordChange.getTime() >= passwordChangeInterval) {
        console.log('You are required to change your password due to security reasons.');
        return res.json({
          _id: user._id,
          name: user.name,
          email: user.email,
          isAdmin: user.isAdmin,
          token: generateToken(user._id),
          changePasswordRequired: true,
        });
      } else {
        // Reset failed login attempts upon successful login
        if (loginAttempts[email]) {
          delete loginAttempts[email];
        }

        return res.json({
          _id: user._id,
          name: user.name,
          email: user.email,
          isAdmin: user.isAdmin,
          token: generateToken(user._id),
          changePasswordRequired: false,
        });
      }
    } else {
      // Invalid password
      if (!loginAttempts[email]) {
        loginAttempts[email] = {
          attempts: 1,
          lastAttempt: new Date().getTime(),
        };
      } else {
        loginAttempts[email].attempts++;
        loginAttempts[email].lastAttempt = new Date().getTime();
      }

      const remainingAttempts = maxLoginAttempts - loginAttempts[email].attempts;
      let errorMessage = 'Invalid email or password';

      if (remainingAttempts > 0) {
        errorMessage += `. ${remainingAttempts} ${remainingAttempts === 1 ? 'attempt' : 'attempts'} left.`;
      } else {
        errorMessage += ` Account locked. Try again later in 1 minute.`;
      }

      res.status(401).json({ message: errorMessage });
    }
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
});



// @desc    Register a new user
// @route   POST /api/users
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error('User already exists');
  }

  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{8,}$/;

  if (!passwordRegex.test(password)) {
    res.status(400);
    throw new Error('Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long');
  }

  const lowercasePassword = password.toLowerCase();
  const lowercaseName = name.toLowerCase();
  const lowercaseEmail = email.toLowerCase();

  if (lowercasePassword.includes(lowercaseName) || lowercasePassword.includes(lowercaseEmail)) {
    res.status(400);
    throw new Error('Password cannot contain your name or email');
  }

  const user = await User.create({
    name,
    email,
    password,
  });

  if (user) {
    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      isAdmin: user.isAdmin,
      lastPasswordChange: Date.now(),
      token: generateToken(user._id),
    });
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});


// @desc    Get user profile
// @route   GET /api/users/profile
// @access  Private
const getUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id)

  if (user) {
    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      isAdmin: user.isAdmin,
    })
  } else {
    res.status(404)
    throw new Error('User not found')
  }
})

// @desc    Update user profile
// @route   PUT /api/users/profile
// @access  Private
const updateUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id)

  if (user) {
    user.name = req.body.name || user.name
    user.email = req.body.email || user.email
    if (req.body.password) {
      user.password = req.body.password
    }

    const updatedUser = await user.save()

    res.json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      isAdmin: updatedUser.isAdmin,
      lastPasswordChange: Date.now(),
      token: generateToken(updatedUser._id),
    })
  } else {
    res.status(404)
    throw new Error('User not found')
  }
})

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
const getUsers = asyncHandler(async (req, res) => {
  const users = await User.find({})
  res.json(users)
})

// @desc    Delete user
// @route   DELETE /api/users/:id
// @access  Private/Admin
const deleteUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id)

  if (user) {
    await user.remove()
    res.json({ message: 'User removed' })
  } else {
    res.status(404)
    throw new Error('User not found')
  }
})

// @desc    Get user by ID
// @route   GET /api/users/:id
// @access  Private/Admin
const getUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id).select('-password')

  if (user) {
    res.json(user)
  } else {
    res.status(404)
    throw new Error('User not found')
  }
})

// @desc    Update user
// @route   PUT /api/users/:id
// @access  Private/Admin
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id)

  if (user) {
    user.name = req.body.name || user.name
    user.email = req.body.email || user.email
    user.isAdmin = req.body.isAdmin

    const updatedUser = await user.save()

    res.json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      isAdmin: updatedUser.isAdmin,
    })
  } else {
    res.status(404)
    throw new Error('User not found')
  }
})

export {
  authUser,
  registerUser,
  getUserProfile,
  updateUserProfile,
  getUsers,
  deleteUser,
  getUserById,
  updateUser,
}
