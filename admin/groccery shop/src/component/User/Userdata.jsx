import React, { useEffect, useState } from 'react'
import './Userdata.css'
const Userdata = () => {
    const [users, setUsers] = useState([]);

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await fetch(`http://localhost:8081/users`);
                if (response.ok) {
                    const data = await response.json();
                    setUsers(data);
                } else {
                    throw new Error('Failed to fetch users');
                }
            } catch (error) {
                console.error(error);
            }
        };

        fetchUsers();
    }, []);
    const handleMessageClick = (email) => {
        window.location.href = `mailto:${email}`;
    };
    const handleDataDeleteClick = async (userId) => {
        try {
            const response = await fetch(`http://localhost:8081/users/${userId}`, {
                method: 'DELETE',
            });
            if (response.ok) {
                // If deletion is successful, fetch updated user data
                setUsers(prevUsers => prevUsers.filter(user => user._id !== userId));
            } else {
                throw new Error('Failed to delete user data');
            }
        } catch (error) {
            console.error(error);
        }
    };
    const handleStarClick = (userId, rating) => {
        // Logic to update the rating for the user
        // For demonstration, let's assume we update the user's rating in the state
        setUsers(prevUsers =>
            prevUsers.map(user => {
                if (user._id === userId) {
                    user.rating = rating; // Assuming user.rating exists in the user object
                }
                return user;
            })
        );
    };

    return (
        <>
            <p>User:</p>
            <br />
            {/* <ul>
                {users.map(user => (
                    <li key={user._id}>
                        <img src={user.image} height={"100px"} width={"100px"} />   {user.firstname} {user.lastname} - {user.email} - {user.email} {user.password}
                    </li>
                ))}
            </ul> */}
            <div className="user-cards-container">
                {users.map(user => (
                    <div className="user-card" key={user._id}>
                        <div className="user-info">
                            <img src={user.image} alt="User Avatar" className="avatar" height={"100px"} width={"100px"} />
                            <div className="details">
                                <h2>{user.firstname} {user.lastname}</h2>
                                <p>Email: {user.email}</p>
                                <p>password:{user.password}</p>
                            </div>
                        </div>
                        <div className="user-actions">
                            <button className="follow-button" onClick={() => handleDataDeleteClick(user._id)}>delete</button>
                            <button className="message-button" onClick={() => handleMessageClick(user.email)}>Message</button>
                        </div>
                        <div className="rating">
                            {[1, 2, 3, 4, 5].map((star, index) => (
                                <span
                                    key={index}
                                    className={index < user.rating ? 'star selected' : 'star'}
                                    onClick={() => handleStarClick(user._id, index + 1)}
                                >
                                    &#9733;
                                </span>
                            ))}
                        </div>
                    </div>
                ))}
            </div>



        </>
    )
}

export default Userdata