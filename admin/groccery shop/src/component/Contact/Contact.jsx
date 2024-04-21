import React, { useEffect, useState } from 'react'
import './Contact.css'
import contact from '../../assets/contact.jpeg'
const Contact = () => {
    const [submissions, setSubmissions] = useState([]);

    useEffect(() => {
        fetchSubmissions();
    }, []);

    const fetchSubmissions = async () => {
        try {
            // Fetch contact form submissions from the backend
            const response = await fetch('http://localhost:8081/contact');
            if (response.ok) {
                const submissionsData = await response.json();
                setSubmissions(submissionsData);
            } else {
                throw new Error('Failed to fetch contact submissions');
            }
        } catch (error) {
            console.error(error);
        }
    };
    const handleMessageClick = (email) => {
        window.location.href = `mailto:${email}`;
    };
    return (

        // <div className="contact-submissions-container">
        //     <h1>Contact Form Submissions</h1>
        //     {submissions.map(submission => (
        //         <div className="contact-submission" key={submission._id}>
        //             <div className="submission-info">
        //                 <p><strong>Name:</strong> {submission.name}</p>
        //                 <p><strong>Email:</strong> {submission.email}</p>
        //                 <p><strong>Subject:</strong> {submission.subject}</p>
        //                 <p><strong>Message:</strong> {submission.message}</p>
        //             </div>
        //             <div className="submission-actions">
        //                 {/* Add any actions you want to perform on the submission */}
        //             </div>
        //         </div>
        //     ))}
        // </div>
        <div className="user-cards-container">
            {submissions.map(submissions => (
                <div className="user-card" key={submissions._id}>
                    <div className="user-info">
                        <img src={contact} alt="User Avatar" className="avatar" height={"100px"} width={"100px"} />
                        <div className="details">
                            <h2><strong>Name:</strong>{submissions.name} </h2>
                            <p><strong>Email:</strong> {submissions.email}</p>
                            <p><strong>Subject:</strong>{submissions.subject}</p>
                            <p><strong>Message:</strong> {submissions.message}</p>
                        </div>
                    </div>
                    <div className="user-actions">
                        {/* <button className="follow-button" onClick={() => handleDataDeleteClick(user._id)}>delete</button> */}
                        <button className="message-button" onClick={() => handleMessageClick(submissions.email)}>Message</button>
                    </div>
                    {/* <div className="rating">
                        {[1, 2, 3, 4, 5].map((star, index) => (
                            <span
                                key={index}
                                className={index < user.rating ? 'star selected' : 'star'}
                                onClick={() => handleStarClick(user._id, index + 1)}
                            >
                                &#9733;
                            </span>
                        ))}
                    </div> */}
                </div>
            ))}
        </div>
    );
}



export default Contact