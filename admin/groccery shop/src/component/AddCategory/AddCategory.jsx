import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import crossIcon from '../../assets/Red-Close-Button-Transparent.png';
const AddCategory = () => {
    const { id } = useParams();
    const navigate = useNavigate();

    const [categories, setCategories] = useState([]);
    const [categoryData, setCategoryData] = useState({
        name: ''
    });

    useEffect(() => {
        const fetchCategories = async () => {
            try {
                const response = await fetch('http://localhost:8081/categories');
                if (response.ok) {
                    const categoriesData = await response.json();
                    setCategories(categoriesData);
                } else {
                    console.error('Failed to fetch categories');
                }
            } catch (error) {
                console.error('Error fetching categories:', error);
            }
        };

        fetchCategories();
    }, []);

    useEffect(() => {
        if (id) {
            const fetchCategoryData = async () => {
                try {
                    const response = await fetch(`http://localhost:8081/categories/${id}`);
                    if (response.ok) {
                        const category = await response.json();
                        setCategoryData(category);
                    } else {
                        console.error('Failed to fetch category');
                    }
                } catch (error) {
                    console.error('Error fetching category:', error);
                }
            };

            fetchCategoryData();
        }
    }, [id]);

    const handleInputChange = (e) => {
        setCategoryData({
            ...categoryData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        try {
            const requestOptions = {
                method: id ? 'PUT' : 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(categoryData)
            };

            const response = await fetch(`http://localhost:8081/categories${id ? `/${id}` : ''}`, requestOptions);

            if (response.ok) {
                const data = await response.json();
                const { category } = data;
                if (id) {
                    // Update existing category
                    const updatedCategories = categories.map(cat => (cat._id === id ? category : cat));
                    setCategories(updatedCategories);
                } else {
                    // Add new category
                    setCategories([...categories, category]);
                }
                setCategoryData({ name: '' }); // Clear the form
                console.log('Category saved:', category);
                // if (!id) {
                navigate('/categories'); // Redirect to category list after successful addition
                // }
            } else {
                console.error('Failed to save category');
            }
        } catch (error) {
            console.error('Error saving category:', error);
        }
    };

    const handleDelete = async (categoryId) => {
        if (window.confirm('Are you sure you want to delete this category?')) {
            try {
                const response = await fetch(`http://localhost:8081/categories/${categoryId}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    navigate('/categories'); // Redirect to category list after successful deletion
                    // Update categories state to reflect the changes
                    const updatedCategories = categories.filter(cat => cat._id !== categoryId);
                    setCategories(updatedCategories);
                } else {
                    console.error('Failed to delete category');
                }
            } catch (error) {
                console.error('Error deleting category:', error);
            }
        }
    };

    return (
        <div>
            {/* <h1>Manage Categories</h1> */}
            <div>
                <h1>{id ? 'Edit category' : 'Add category'}</h1>
                <form onSubmit={handleSubmit}>
                    <label>
                        Category Name:
                        <input
                            type="text"
                            name="name"
                            value={categoryData.name}
                            onChange={handleInputChange}
                            required
                            style={{
                                padding: '10px',
                                borderRadius: '5px',
                                border: '1px solid #ccc',
                                marginBottom: '10px',
                                width: '100%',
                            }}
                        />
                    </label>
                    <button
                        type="submit"
                        style={{
                            padding: '10px 20px',
                            backgroundColor: '#007bff',
                            color: '#fff',
                            borderRadius: '5px',
                            border: 'none',
                            cursor: 'pointer',
                        }}
                    >
                        {id ? 'Update Category' : 'Add Category'}
                    </button>
                </form>

            </div>
            <div>
                <h2>All Categories</h2>
                <div className='mr'>
                    <div className="container">
                        <div className="row main">
                            <div className="col-md-offset-1 col-md-10">
                                <div className="panel">
                                    <div className="panel-body table-responsive">
                                        <table className="table">
                                            <thead>
                                                <tr>

                                                    <th>Category ID</th>
                                                    <th>Category Name</th>

                                                    <th>Action</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {categories.map(category => (
                                                    <tr key={category._id}>
                                                        <td>{category._id}</td>
                                                        <td>{category.name}</td>
                                                        <td className="action-icons">
                                                            <Link to={`/categories/${category._id}`} className="edit-icon" title="Edit">
                                                                <i className="fa fa-edit"></i>
                                                            </Link>
                                                            <a href="#" onClick={() => handleDelete(category._id)} title="Delete">
                                                                <img src={crossIcon} alt="Delete" style={{ height: '25px', width: '30px' }} />
                                                            </a>
                                                        </td>
                                                        {/* <td>
                                                            <Link to={`/categories/${category._id}`}>Edit</Link>
                                                            <button onClick={() => handleDelete(category._id)}>Delete</button>
                                                        </td> */}
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default AddCategory;
