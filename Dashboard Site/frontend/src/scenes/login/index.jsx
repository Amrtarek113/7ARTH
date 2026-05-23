import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { TextField, Button, Typography, Container, Box, useTheme } from '@mui/material';
import { tokens } from '../../theme';

const Login = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); // clear previous error
    try {
      const response = await axios.post('http://localhost:8080/api/auth/login', {
        username,
        password,
      });

      if (response.data.status === 'success') {
        const { token, user } = response.data.data;
        // Save the token and user info if needed
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));

        // Optionally set axios default header for future requests
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

        // Navigate to home or dashboard
        navigate('/');
      } else {
        setError(response.data.message || 'Login failed');
      }
    } catch (err) {
      if (err.response) {
        // Server responded with error status
        setError(err.response.data.message || 'Login failed. Please try again.');
      } else if (err.request) {
        // No response received
        setError('No response from server. Check your connection.');
      } else {
        // Other errors
        setError('An unexpected error occurred.');
      }
    }
  };

  return (
    <Container maxWidth="sm" sx={{ mt: 8 }}>
      <Box
        sx={{
          backgroundColor: colors.primary[400],
          p: 4,
          borderRadius: '8px',
          boxShadow: `0 4px 8px ${colors.primary[500]}`,
        }}
      >
        <Typography
          variant="h4"
          gutterBottom
          color={colors.grey[100]}
          fontWeight="bold"
          align="center"
        >
          Login
        </Typography>
        <form onSubmit={handleSubmit}>
          <TextField
            label="Username"
            fullWidth
            margin="normal"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            variant="outlined"
            InputLabelProps={{ style: { color: colors.grey[100] } }}
            InputProps={{
              style: { color: colors.grey[100], backgroundColor: colors.primary[500] },
            }}
          />
          <TextField
            label="Password"
            type="password"
            fullWidth
            margin="normal"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            variant="outlined"
            InputLabelProps={{ style: { color: colors.grey[100] } }}
            InputProps={{
              style: { color: colors.grey[100], backgroundColor: colors.primary[500] },
            }}
          />
          <Button
            type="submit"
            fullWidth
            sx={{
              backgroundColor: colors.blueAccent[700],
              color: colors.grey[100],
              fontSize: '14px',
              fontWeight: 'bold',
              padding: '10px 20px',
              mt: 2,
              '&:hover': { backgroundColor: colors.blueAccent[800] },
            }}
          >
            Login
          </Button>
          {error && (
            <Typography
              color="error"
              sx={{ mt: 2, textAlign: 'center' }}
            >
              {error}
            </Typography>
          )}
        </form>
      </Box>
    </Container>
  );
};
export default Login;