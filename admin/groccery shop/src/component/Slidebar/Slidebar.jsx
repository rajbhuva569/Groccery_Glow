import React from 'react'
import './Slidebar.css'
import { Link } from 'react-router-dom'
import add_product_icon from '../../assets/Product_Cart.svg'
import list_product_icon from '../../assets/Product_list_icon.svg'
import user from '../../assets/user.jpeg'
import contact from '../../assets/contact-icons-png-3.png'
import category from '../../assets/category.jpeg'
const Slidebar = () => {
    return (
        <div className='slidebar'>
            <Link to={'/addproduct'} style={{ textDecoration: "none" }}>
                <div className='sidebar-item'>
                    <img src={add_product_icon} alt='' height={"30px"} />
                    <p>Add product</p>
                </div>
            </Link>
            <Link to={'/listproduct'} style={{ textDecoration: "none" }}>
                <div className='sidebar-item'>
                    <img src={list_product_icon} alt='' height={"30px"} />
                    <p>Product list</p>
                </div>
            </Link>

            <Link to={'/user'} style={{ textDecoration: "none" }}>
                <div className='sidebar-item'>
                    <img src={user} alt='' height={"40px"} />
                    <p>User data</p>
                </div>
            </Link>
            <Link to={'/orders'} style={{ textDecoration: "none" }}>
                <div className='sidebar-item'>
                    <img src={list_product_icon} alt='' />
                    <p>Order data</p>
                </div>
            </Link>
            <Link to={'/contact'} style={{ textDecoration: "none" }}>
                <div className='sidebar-item'>
                    <img src={contact} alt='' height={"40px"} />
                    <p>Contact data</p>
                </div>
            </Link>
            <Link to={'/categories'} style={{ textDecoration: "none" }}>
                <div className='sidebar-item'>
                    <img src={category} alt='' height={"30px"} />
                    <p>Category data</p>
                </div>
            </Link>
        </div>
    )
}

export default Slidebar