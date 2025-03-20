import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const Signup = () => {
    const [email, setEmail] = useState('');
    const [otp, setOtp] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [step, setStep] = useState('email'); // 'email' or 'otp'
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const navigate = useNavigate();

    const handleEmailSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        try {
            const response = await axios.post('http://localhost:3000/api/signup', { email });
            if (response.data.success) {
                setSuccess(response.data.message);
                setStep('otp');
            } else {
                setError(response.data.message || 'Signup failed.');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to send OTP. Please try again.');
        }
    };

    const handleOtpSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        if (password !== confirmPassword) {
            setError('Passwords do not match.');
            return;
        }

        try {
            const response = await axios.post('http://localhost:3000/api/verify-otp', {
                email,
                otp,
                password,
                confirmPassword
            });
            if (response.data.success) {
                setSuccess('Account created successfully! Redirecting to login...');
                setTimeout(() => {
                    navigate('/login');
                }, 2000);
            } else {
                setError(response.data.errors?.otp || response.data.message || 'OTP verification failed.');
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to verify OTP. Please try again.');
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

            <h2 style={{ textAlign: 'center' }}>Sign Up</h2>

            {error && <p style={{ color: 'red', textAlign: 'center' }}>{error}</p>}
            {success && <p style={{ color: 'green', textAlign: 'center' }}>{success}</p>}

            {step === 'email' ? (
                <form onSubmit={handleEmailSubmit}>
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
                        Send OTP
                    </button>
                </form>
            ) : (
                <form onSubmit={handleOtpSubmit}>
                    <div>
                        <label>Enter OTP:</label>
                        <input
                            type="text"
                            value={otp}
                            onChange={(e) => setOtp(e.target.value)}
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
                    <div>
                        <label>Confirm Password:</label>
                        <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
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
                        Verify OTP & Sign Up
                    </button>
                </form>
            )}
        </div>
    );
};

export default Signup;