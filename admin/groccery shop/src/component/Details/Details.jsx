import React, { useEffect, useState } from 'react';
import './Details.css'
const Details = () => {
    const [products, setProducts] = useState([]);
    const [users, setUsers] = useState([]);
    const [categories, setCategories] = useState([]);
    const [contacts, setContacts] = useState([]);
    const [productCount, setProductCount] = useState(0);
    const [userCount, setUserCount] = useState(0);
    const [categoryCount, setCategoryCount] = useState(0);
    const [contactCount, setContactCount] = useState(0);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const productResponse = await fetch('http://localhost:8081/products');
                const userResponse = await fetch('http://localhost:8081/users');
                const categoryResponse = await fetch('http://localhost:8081/categories');
                const contactResponse = await fetch('http://localhost:8081/contact');

                if (productResponse.ok && userResponse.ok && categoryResponse.ok && contactResponse.ok) {
                    const productsData = await productResponse.json();
                    const usersData = await userResponse.json();
                    const categoriesData = await categoryResponse.json();
                    const contactsData = await contactResponse.json();

                    setProducts(productsData);
                    setUsers(usersData);
                    setCategories(categoriesData);
                    setContacts(contactsData);

                    // Update counts
                    setProductCount(productsData.length);
                    setUserCount(usersData.length);
                    setCategoryCount(categoriesData.length);
                    setContactCount(contactsData.length);
                } else {
                    throw new Error('Failed to fetch data');
                }
            } catch (error) {
                console.error(error);
            }
        };

        fetchData();
    }, []);

    return (


        <div className="container1">
            <div className="row d">
                <div className="col-lg-4 col-md-6 col-sm-6">
                    <div className="card-counter primary">
                        <i className="fa fa-cubes"></i>
                        <p className="count-numbers">{productCount}</p>
                        <span className="count-name">Product</span>
                    </div>
                </div>

                <div className="col-lg-4 col-md-6 col-sm-6">
                    <div className="card-counter danger">
                        <i className="fa fa-user"></i>
                        <p className="count-numbers">{userCount}</p>
                        <span className="count-name">User</span>
                    </div>
                </div>

                <div className="col-lg-2 col-md-6 col-sm-6">
                    <div className="card-counter success">
                        <i className="fa fa-list"></i>
                        <p className="count-numbers">{categoryCount}</p>
                        <span className="count-name">Category</span>
                    </div>
                </div>

                <div className="col-lg-4 col-md-6 col-sm-6">
                    <div className="card-counter info">
                        <i className="fa fa-address-book"></i>
                        <p className="count-numbers">{contactCount}</p>
                        <span className="count-name">Contact</span>
                    </div>
                </div>
            </div>
        </div>


    );
};

export default Details;
