import React, { useState } from 'react';
import axios from 'axios';

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        try {
            const response = await axios.post('http://localhost:3000/api/login', { email, password });
            if (response.data.success) {
                setSuccess('Login successful!');
                console.log('Access Token:', response.data.accessToken);
                console.log('Refresh Token:', response.data.refreshToken);
            } else {
                setError(response.data.message || 'Login failed.');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to login. Please try again.');
        }
    };

    return (
        <div style={{ maxWidth: '400px', margin: '50px auto', padding: '20px', border: '1px solid #ccc', borderRadius: '5px' }}>
            {/* Updated logo URL to use the public directory */}
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
                <img
                    src="http://localhost:3000/public/logo.png"
                    alt="RecruitPro Logo"
                    style={{ width: '100px' }}
                    onError={(e) => (e.target.src = 'https://via.placeholder.com/100?text=Logo')} // Fallback image
                />
            </div>

            <h2 style={{ textAlign: 'center' }}>Login</h2>
            {error && <p style={{ color: 'red', textAlign: 'center' }}>{error}</p>}
            {success && <p style={{ color: 'green', textAlign: 'center' }}>{success}</p>}
            <form onSubmit={handleSubmit}>
                <div>
                    <label>Email:</label>
                    <input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        style={{ width: '100%', padding: '8px', margin: '10px 0', borderRadius: '4px', border: '1px solid #ccc' }}
                    />
                </div>
                <div>
                    <label>Password:</label>
                    <input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        style={{ width: '100%', padding: '8px', margin: '10px 0', borderRadius: '4px', border: '1px solid #ccc' }}
                    />
                </div>
                <button
                    type="submit"
                    style={{
                        width: '100%',
                        padding: '10px',
                        background: '#007bff',
                        color: '#fff',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer'
                    }}
                >
                    Login
                </button>
            </form>
        </div>
    );
};

export default Login;