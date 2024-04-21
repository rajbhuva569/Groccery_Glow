import React, { useEffect, useState } from 'react';
import './Addproduct.css';
import upload_area from '../../assets/upload_area.svg';
import { ImagetoBase64 } from '../../../../../fronted/src/utility/imageToBase64';
import { Navigate, useNavigate, useParams } from 'react-router-dom';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const Addproduct = () => {
    const navigate = useNavigate();
    const { id } = useParams();
    console.log(id);
    const [data, setData] = useState({
        name: '',
        category: '',
        image: '',
        price: '',
        description: ''
    });
    const [errors, setErrors] = useState({
        name: '',
        category: '',
        image: '',
        price: '',
        description: ''
    });
    useEffect(() => {
        // Fetch product data if editing an existing product
        if (id) {
            const fetchProduct = async () => {
                try {
                    const response = await fetch(`http://localhost:8081/editproduct/${id}`, {
                        method: 'PUT',
                    });

                    if (response.ok) {
                        const productData = await response.json();
                        console.log("Product Data:", productData);

                        setData({
                            name: productData.data.name,
                            category: productData.data.category,
                            image: productData.data.image,
                            price: productData.data.price,
                            description: productData.data.description,
                        });
                    } else {
                        console.error('Failed to fetch product. Status:', response.status);
                    }
                } catch (error) {
                    console.error('Error fetching product:', error);
                }
            };

            fetchProduct();
        }
    }, [id]);

    const handleOnChange = (e) => {
        const { name, value } = e.target;
        setData((prev) => {
            return {
                ...prev,
                [name]: value
            };
        });
    };

    const uploadImage = async (e) => {
        const imageData = await ImagetoBase64(e.target.files[0]);
        setData((prev) => {
            return {
                ...prev,
                image: imageData
            };
        });
    };

    const [categories, setCategories] = useState([]);

    useEffect(() => {
        const fetchCategories = async () => {
            try {
                const response = await fetch('http://localhost:8081/categories');
                if (response.ok) {
                    const categoriesData = await response.json();
                    setCategories(categoriesData);
                } else {
                    console.error('Failed to fetch categories. Status:', response.status);
                }
            } catch (error) {
                console.error('Error fetching categories:', error);
            }
        };

        fetchCategories();
    }, []);

    const validateForm = () => {
        const errors = {};

        if (!data.name) {
            errors.name = 'Name is required';
        }
        if (!data.image) {
            errors.image = 'Image is required';
        }
        if (!data.category) {
            errors.category = 'Category is required';
        }
        if (!data.price) {
            errors.price = 'Price is required';
        }
        if (!data.description) {
            errors.description = 'Description is required';
        }

        setErrors(errors);

        // Return true if there are no errors, false otherwise
        return Object.keys(errors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        // Validate the form
        const isValid = validateForm();

        if (!isValid) {
            // If form is not valid, exit the function
            return;
        }

        try {
            // Determine whether to add or update the product based on the presence of ID
            const url = id ? `http://localhost:8081/editproduct/${id}` : 'http://localhost:8081/uploadProduct';
            const method = id ? 'PUT' : 'POST'; // Use 'PUT' for update, 'POST' for add

            const fetchData = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            if (!fetchData.ok) {
                throw new Error(`HTTP error! Status: ${fetchData.status}`);
            }

            const responseData = await fetchData.json();

            // Update the state with the response data
            setData(responseData.data);

            // Reset the form data
            setData({
                name: '',
                category: '',
                image: '',
                price: '',
                description: '',
            });

            toast.success('Product added successfully!');
        } catch (error) {
            console.error('Error fetching data:', error);
            toast.error('An error occurred while adding the product.');
        }
    };

    return (
        <div className='add-product'>
            <h1>{id ? 'Edit Product' : 'Add Product'}</h1>
            <div>
                <form onSubmit={handleSubmit}>
                    <div className='addproduct-itemfield'>
                        <label htmlFor='name'>Name:</label>
                        <input type='text' name='name' className='bg-slate-200 p-1 my-1' onChange={handleOnChange} value={data.name} />
                        {errors.name && <span className="text-red-600" style={{ color: 'red' }}>{errors.name}</span>}
                    </div>
                    <div className='addproduct-itemfield'>
                        <label htmlFor='category'>Category:</label>
                        <select className='bg-slate-200 p-1 my-1' name='category' onChange={handleOnChange} value={data.category}>
                            <option value=''>Select category</option>
                            {categories.map(category => (
                                <option key={category._id} value={category.name}>{category.name}</option>
                            ))}
                        </select>
                        {errors.category && <span className="text-red-500" style={{ color: 'red' }}>{errors.category}</span>}
                    </div>
                    <div className='addproduct-itemfield'>
                        <label htmlFor='image'>image:
                            <div className='h-40 w-full bg-slate-300  rounded flex items-center justify-center'>
                                <img className='h-full' src={upload_area} />
                                {data.image ? <img height={'100px'} width={'100px'} src={data.image} /> : <span className='text-5xl'></span>
                                }


                                <input type='file' accept='image/*' id='image' className='hidden' onChange={uploadImage} hidden />
                                {errors.image && <span className="text-red-500" style={{ color: 'red' }}>{errors.image}</span>}
                            </div>
                        </label>
                    </div>
                    <div className='addproduct-itemfield'>
                        <label htmlFor='price'>Price:</label>
                        <input type='number' className='bg-slate-200 p-1 my-1' name='price' onChange={handleOnChange} value={data.price} />
                        {errors.price && <span className="text-red-500" style={{ color: 'red' }}>{errors.price}</span>}
                    </div>
                    <div className='addproduct-itemfield'>
                        <label htmlFor='description'>Description:</label>
                        <textarea rows={3} className='bg-slate-200 p-1 my-1 resize-none' name='description' onChange={handleOnChange} value={data.description} />
                        {errors.description && <span className="text-red-500" style={{ color: 'red' }}>{errors.description}</span>}
                    </div>
                    <button className='addproduct-btn'>{id ? 'Save Changes' : 'Add Product'}</button>
                </form>
            </div>
        </div>
    );
};

export default Addproduct;


// import React, { useEffect, useState } from 'react'
// import './Addproduct.css'
// import upload_area from '../../assets/upload_area.svg'
// import { ImagetoBase64 } from '../../../../../fronted/src/utility/imageToBase64'
// import { Navigate, useNavigate, useParams } from 'react-router-dom'
// import { ToastContainer, toast } from 'react-toastify';
// import 'react-toastify/dist/ReactToastify.css';

// const Addproduct = () => {
//     const navigate = useNavigate()
//     const { id } = useParams();
//     console.log(id);
//     const [data, setData] = useState({
//         name: '',
//         category: '',
//         image: '',
//         price: '',
//         description: ''
//     })
//     const [errors, setErrors] = useState({
//         name: '',
//         category: '',
//         image: '',
//         price: '',
//         description: ''
//     });
//     useEffect(() => {
//         // Fetch product data if editing an existing product
//         if (id) {
//             const fetchProduct = async () => {
//                 try {
//                     const response = await fetch(`http://localhost:8081/editproduct/${id}`, {
//                         method: 'PUT',
//                     });

//                     if (response.ok) {
//                         const productData = await response.json();
//                         console.log("Product Data:", productData);

//                         setData({
//                             name: productData.data.name,
//                             category: productData.data.category._id,
//                             image: productData.data.image,
//                             price: productData.data.price,
//                             description: productData.data.description,
//                         });
//                     } else {
//                         console.error('Failed to fetch product. Status:', response.status);
//                     }
//                 } catch (error) {
//                     console.error('Error fetching product:', error);
//                 }
//             };

//             fetchProduct();
//         }
//     }, [id]);

//     // useEffect(() => {
//     //     // Fetch product data if editing an existing product
//     //     if (id) {
//     //         const fetchProduct = async () => {
//     //             try {
//     //                 const response = await fetch(`http://localhost:8081/editproduct/${id}`, {
//     //                     method: 'PUT',
//     //                 });

//     //                 if (response.ok) {
//     //                     const productData = await response.json();
//     //                     console.log("Product Data:", productData);

//     //                     setData({
//     //                         name: productData.data.name,
//     //                         category: productData.data.category._id,
//     //                         image: productData.data.image,
//     //                         price: productData.data.price,
//     //                         description: productData.data.description,
//     //                     });
//     //                 } else {
//     //                     console.error('Failed to fetch product. Status:', response.status);
//     //                 }
//     //             } catch (error) {
//     //                 console.error('Error fetching product:', error);
//     //             }
//     //         };



//     //         fetchProduct();
//     //     }
//     // }, [id]);

//     const handleOnChange = (e) => {
//         const { name, value } = e.target
//         setData((prev) => {
//             return {
//                 ...prev,
//                 [name]: value
//             }
//         })
//     }

//     const uploadImage = async (e) => {
//         const data = await ImagetoBase64(e.target.files[0])
//         // console.log(data);
//         setData((prev) => {
//             return {
//                 ...prev,
//                 image: data
//             }
//         })

//     }
//     // const handleSubmit = async (e) => {
//     //     e.preventDefault();
//     //     console.log(data);

//     //     const { name, image, category, price } = data;

//     //     if (name && image && category && price) {
//     //         try {
//     //             const fetchData = await fetch(`http://localhost:8081/uploadProduct`, {
//     //                 method: 'POST',
//     //                 headers: {
//     //                     'Content-Type': 'application/json',
//     //                 },
//     //                 body: JSON.stringify(data),
//     //             });

//     //             if (!fetchData.ok) {
//     //                 throw new Error(`HTTP error! Status: ${fetchData.status}`);
//     //             }

//     //             // Reset the form data
//     //             setData({
//     //                 name: '',
//     //                 category: '',
//     //                 image: '',
//     //                 price: '',
//     //                 description: '',
//     //             });

//     //             // Handle the response accordingly
//     //             const fetchRes = await fetchData.json();
//     //             console.log(fetchRes);
//     //             // You can perform additional actions or show a success message
//     //         } catch (error) {
//     //             console.error('Error fetching data:', error);
//     //             // Handle error or display a message to the user
//     //         }
//     //     } else {
//     //         // toast("Enter a required field")
//     //     }
//     // };
//     const [categories, setCategories] = useState([]);

//     useEffect(() => {
//         const fetchCategories = async () => {
//             try {
//                 const response = await fetch('http://localhost:8081/categories');
//                 if (response.ok) {
//                     const categoriesData = await response.json();
//                     setCategories(categoriesData);
//                 } else {
//                     console.error('Failed to fetch categories. Status:', response.status);
//                 }
//             } catch (error) {
//                 console.error('Error fetching categories:', error);
//             }
//         };

//         fetchCategories();
//     }, []);

//     const validateForm = () => {
//         const errors = {};

//         if (!data.name.trim()) {
//             errors.name = 'Name is required';
//         }
//         if (!data.image.trim()) {
//             errors.image = 'Image is required';
//         }
//         if (!data.category.trim()) {
//             errors.category = 'Category is required';
//         }
//         if (!data.price.trim()) {
//             errors.price = 'Price is required';
//         }
//         if (!data.description.trim()) {
//             errors.description = 'Description is required';
//         }

//         setErrors(errors);

//         // Return true if there are no errors, false otherwise
//         return Object.keys(errors).length === 0;
//     };

//     const handleSubmit = async (e) => {
//         e.preventDefault();

//         // Validate the form
//         const isValid = validateForm();

//         if (!isValid) {
//             // If form is not valid, exit the function
//             return;
//         }

//         // const { name, image, category, price, description } = data;

//         try {
//             // Determine whether to add or update the product based on the presence of ID
//             const url = id ? `http://localhost:8081/editproduct/${id}` : 'http://localhost:8081/uploadProduct';
//             const method = id ? 'PUT' : 'POST'; // Use 'PUT' for update, 'POST' for add

//             const fetchData = await fetch(url, {
//                 method,
//                 headers: {
//                     'Content-Type': 'application/json',
//                 },
//                 body: JSON.stringify(data),
//             });

//             if (!fetchData.ok) {
//                 throw new Error(`HTTP error! Status: ${fetchData.status}`);
//             }

//             const responseData = await fetchData.json();

//             // Update the state with the response data
//             setData(responseData.data);

//             // Reset the form data
//             setData({
//                 name: '',
//                 category: '',
//                 image: '',
//                 price: '',
//                 description: '',
//             });

//             toast.success('Product added successfully!');
//             // Navigate back to the product list after successful addition/update
//             // navigate('/addproduct');
//         } catch (error) {
//             console.error('Error fetching data:', error);
//             toast.error('An error occurred while adding the product.');
//             // Handle error or display a message to the user
//         }
//     };

//     // const handleSubmit = async (e) => {
//     //     e.preventDefault();

//     //     const { name, image, category, price, description } = data;
//     //     const validationErrors = {};
//     //     if (!name.trim()) {
//     //         validationErrors.name = 'Name is required';
//     //     }
//     //     if (!image.trim()) {
//     //         validationErrors.name = 'image is required';
//     //     }
//     //     if (!category.trim()) {
//     //         validationErrors.name = 'category is required';
//     //     }
//     //     if (!price.trim()) {
//     //         validationErrors.name = 'price is required';
//     //     }
//     //     if (!description.trim()) {
//     //         validationErrors.name = 'description is required';
//     //     }
//     //     if (Object.keys(validationErrors).length > 0) {
//     //         // Update the errors state with the validation errors
//     //         setErrors(validationErrors);
//     //         return; // Exit function if there are validation errors
//     //     }
//     //     if (name && image && category && price) {
//     //         try {
//     //             // Determine whether to add or update the product based on the presence of ID
//     //             const url = id ? `http://localhost:8081/editproduct/${id}` : 'http://localhost:8081/uploadProduct';
//     //             const method = id ? 'PUT' : 'POST'; // Use 'PUT' for update, 'POST' for add

//     //             const fetchData = await fetch(url, {
//     //                 method,
//     //                 headers: {
//     //                     'Content-Type': 'application/json',
//     //                 },
//     //                 body: JSON.stringify(data),
//     //             });

//     //             if (!fetchData.ok) {
//     //                 throw new Error(`HTTP error! Status: ${fetchData.status}`);
//     //             }
//     //             const responseData = await fetchData.json();

//     //             // Update the state with the response data
//     //             setData(responseData.data);
//     //             // Reset the form data
//     //             setData({
//     //                 name: '',
//     //                 category: '',
//     //                 image: '',
//     //                 price: '',
//     //                 description: '',
//     //             });
//     //             toast.success('Product added successfully!');
//     //             // Navigate back to the product list after successful addition/update
//     //             navigate('/productList');
//     //         } catch (error) {
//     //             console.error('Error fetching data:', error);
//     //             toast.error('An error occurred while adding the product.');
//     //             // Handle error or display a message to the user
//     //         }
//     //     } else {
//     //         // Handle validation error or display a message
//     //     }
//     // };


//     return (
//         <div className='add-product'>
//             <h1>{id ? 'Edit Product' : 'Add Product'}</h1>
//             <div >
//                 <form onSubmit={handleSubmit}>
//                     <div className='addproduct-itemfield'>
//                         <label htmlFor='name'>name:</label>
//                         <input type={'text'} name='name' className='bg-slate-200 p-1 my-1' onChange={handleOnChange} value={data.name} />
//                         {errors.name && <span className="text-red-600" style={{ color: 'red' }}>{errors.name}</span>}
//                     </div>
//                     {/* <div className='addproduct-itemfield'>
//                         <label htmlFor='category'>Category</label>
//                         <select className='bg-slate-200 p-1 my-1' id='category' name='category' onChange={handleOnChange} value={data.category}>
//                             <option value={"other"}> Selecct category</option>
//                             <option value={'fruites'}>Fruites</option>
//                             <option value={'vegetdable'}>Vegetdable</option>
//                             <option value={'icecream'}>Icecream</option>
//                             <option value={'dosa'}>Dosa</option>
//                             <option value={'pizaa'}>Pizaa </option>
//                         </select>
//                     </div> */}
//                     <div className='addproduct-itemfield'>
//                         <label htmlFor='category'>Category:  </label>
//                         <select className='bg-slate-200 p-1 my-1' name='category' onChange={handleOnChange} value={data.category}>
//                             <option value=''>Select category</option>
//                             {categories.map(category => (
//                                 <option key={category._id} value={category.name}>{category.name}</option>
//                             ))}
//                             {errors.category && <span className="text-red-500" style={{ color: 'red' }}>{errors.category}</span>}
//                         </select>
//                     </div>
//                     <div className='addproduct-itemfield'>
//                         <label htmlFor='image'>image:
//                             <div className='h-40 w-full bg-slate-300  rounded flex items-center justify-center'>
//                                 <img className='h-full' src={upload_area} />
//                                 {data.image ? <img height={'100px'} width={'100px'} src={data.image} /> : <span className='text-5xl'></span>
//                                 }


//                                 <input type='file' accept='image/*' id='image' className='hidden' onChange={uploadImage} hidden />
//                                 {errors.image && <span className="text-red-500" style={{ color: 'red' }}>{errors.image}</span>}
//                             </div>
//                         </label>
//                     </div>
//                     <div className='addproduct-itemfield'>
//                         <label htmlFor='price' className='my-1'>price:</label>
//                         <input type={'number'} className='bg-slate-200 p-1 my-1' name='price' onChange={handleOnChange} value={data.price} />
//                         {errors.price && <span className="text-red-500" style={{ color: 'red' }}>{errors.price}</span>}
//                     </div> <div className='addproduct-itemfield'>
//                         <label htmlFor='description' className='my-1'>description:</label>
//                         <textarea rows={3} className='bg-slate-200 p-1 my-1 resize-none' name='description' onChange={handleOnChange} value={data.description} />
//                         {errors.description && <span className="text-red-500" style={{ color: 'red' }}>{errors.description}</span>}
//                     </div>
//                     <button className='addproduct-btn'>{id ? 'Save Changes' : 'Add Product'}</button>
//                 </form>
//             </div>
//         </div>
//     )
// }

// export default Addproduct