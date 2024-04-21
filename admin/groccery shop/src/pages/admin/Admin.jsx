import React, { useEffect, useState } from 'react';
import './Admin.css';
import Slidebar from '../../component/Slidebar/Slidebar';
import { Routes, Route, useNavigate } from 'react-router-dom';
import Addproduct from '../../component/Addproduct/Addproduct';
import Listproduct from '../../component/Listproduct/Listproduct';
import Userdata from '../../component/User/Userdata';
import Orders from '../../component/paymet/Payment';
import Contact from '../../component/Contact/Contact';
import AddCategory from '../../component/AddCategory/AddCategory';
import Login from '../../component/Login/Login';
import Details from '../../component/Details/Details';

const Admin = () => {
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
       
        const loggedIn = localStorage.getItem('isLoggedIn');
        if (loggedIn === 'true') {
            setIsLoggedIn(true);
        } else {
            
            navigate('/login');
        }
    }, [navigate]);
    return (
        <div>
            <div className='admin'>
                {isLoggedIn && <Slidebar />}
                <Routes>
                    <Route path='/login' element={<Login setIsLoggedIn={setIsLoggedIn} />} />
                    {isLoggedIn && (
                        <>
                            <Route path='/' element={<Details />} />
                            <Route path='/addproduct' element={<Addproduct />} />
                            <Route path='/user' element={<Userdata />} />
                            <Route path='/listproduct' element={<Listproduct />} />
                            <Route path='/editproduct/:id' element={<Addproduct />} />
                            <Route path='/orders' element={<Orders />} />
                            <Route path='/contact' element={<Contact />} />
                            <Route path='/categories' element={<AddCategory />} />
                            <Route path='/categories/:id' element={<AddCategory />} />
                            {/* <Route path='/logout' element={<Logout onLogout={() => } />} /> */}
                        </>
                    )}
                </Routes>
            </div>
        </div>
    );
}

export default Admin;
