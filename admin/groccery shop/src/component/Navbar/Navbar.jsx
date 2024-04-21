import React, { useEffect, useState } from 'react';
import './Navbar.css';
import navlogo from '../../assets/nav-logo.svg';
import navProfile from '../../assets/nav-profile.svg';
import { useNavigate } from 'react-router-dom';

const Navbar = () => {
    const navigate = useNavigate();
    const [isLoggedIn, setIsLoggedIn] = useState(false);
   
    useEffect(() => {
        const loggedIn = localStorage.getItem('isLoggedIn');
        if (loggedIn === 'true') {
            setIsLoggedIn(true);
        } else {
            navigate('/login');
        }
    }, [navigate]);

    const handleProfileClick = () => {
        // Clear logged-in status from localStorage
        localStorage.setItem('isLoggedIn', 'false');
        // Navigate to the login page
        navigate('/login');
    };

    return (
        <div className='navbar'>
            <img src={navlogo} alt='' className='nav-logo' />
            <img src={navProfile} alt='' className='nav-profile' onClick={handleProfileClick} />
        </div>
    );
};

export default Navbar;
// import React, { useEffect, useState } from 'react';
// import './Navbar.css';
// import navlogo from '../../assets/nav-logo.svg';
// import navProfile from '../../assets/nav-profile.svg';
// import exit from '../../assets/vector-logout-sign-icon.jpg';
// import { useNavigate } from 'react-router-dom';

// const Navbar = () => {
//     const [isLoggedIn, setIsLoggedIn] = useState(false);
//     const navigate = useNavigate();
//     const [showImage, setShowImage] = useState(true);

//     const handleImageClick = () => {
//         setShowImage(false);
//     };

//     useEffect(() => {
//         // Check if the user is already logged in based on local storage
//         const storedIsLoggedIn = localStorage.getItem('isLoggedIn');
//         if (storedIsLoggedIn === 'true') {
//             setIsLoggedIn(true);
//         } else {
//             setIsLoggedIn(false);
//         }
//     }, []);

//     const handleLogout = () => {
//         // Clear authentication status and data from local storage
//         localStorage.removeItem('isLoggedIn');
//         setIsLoggedIn(false);
//         // Redirect the user to the login page
//         navigate('/admin/login');
//     };

//     return (
//         <div className='navbar'>
//             {isLoggedIn && (
//                 <img src={navlogo} alt='' className='nav-logo' />
//             )}

//             {/* Render the logout button only if showImage is true */}
//             {isLoggedIn && showImage ? (
//                 <img
//                     src={navProfile}
//                     alt=''
//                     className='nav-profile'
//                     onClick={handleImageClick}
//                 />
//             ) : (
//                 <img
//                     src={exit}
//                     alt=''
//                     className='nav-profile'
//                     onClick={handleLogout}
//                 />
//             )}
//         </div>
//     );
// };

// export default Navbar;
