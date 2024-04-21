import React, { useEffect, useState } from 'react';
import './Listproduct.css';
import crossIcon from '../../assets/Red-Close-Button-Transparent.png';
import { Link } from 'react-router-dom';
import { PDFDownloadLink, Document, Page, Text } from '@react-pdf/renderer';
import { CSVLink } from 'react-csv';

const ProductPDF = ({ products }) => (
    <Document>
        <Page>
            {products?.map((product, index) => (
                <Text key={index}>
                    {product.name}, {product.category}, {product.price}, {product.description}
                </Text>
            ))}
        </Page>
    </Document>
);

const ListProduct = () => {
    const [products, setProducts] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');

    const fetchProducts = async () => {
        try {
            const response = await fetch('http://localhost:8081/products');
            if (response.ok) {
                const productData = await response.json();
                setProducts(productData);
            } else {
                console.error('Failed to fetch products');
            }
        } catch (error) {
            console.error('Error fetching products:', error);
        }
    };

    const handleSearchChange = (event) => {
        setSearchTerm(event.target.value);
    };

    // const removeItem = async (productId) => {
    //     try {
    //         const response = await fetch(`http://localhost:8081/removeProduct/${productId}`, {
    //             method: 'delete',
    //         });

    //         if (response.ok) {
    //             await fetchProducts();
    //         } else {
    //             console.error('Failed to remove product');
    //         }
    //     } catch (error) {
    //         console.error('Error removing product:', error);
    //     }
    // };
    const removeItem = async (productId) => {
        const confirmed = window.confirm("Are you sure you want to delete this item?");
        if (confirmed) {
            try {
                const response = await fetch(`http://localhost:8081/removeProduct/${productId}`, {
                    method: 'delete',
                });

                if (response.ok) {
                    await fetchProducts();
                } else {
                    console.error('Failed to remove product');
                }
            } catch (error) {
                console.error('Error removing product:', error);
            }
        }
    };


    useEffect(() => {
        fetchProducts();
    }, []);

    const filteredProducts = products.filter((product) =>
        product.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        product.category.toLowerCase().includes(searchTerm.toLowerCase()) ||
        product.price.toString().includes(searchTerm.toLowerCase()) ||
        product.description.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="container mr">
            <div className="row main">
                <div className="col-md-offset-1 col-md-10">
                    <div className="panel">
                        <div className="panel-heading">
                            <div className="row">
                                <div className="col col-sm-3 col-xs-12">
                                    <h4 className="title">Data <span>List</span></h4>
                                </div>
                                <div className="col-sm-9 col-xs-12 text-right">
                                    <div className="btn_group">
                                        <input
                                            type="text"
                                            className="form-control"
                                            placeholder="Search"
                                            value={searchTerm}
                                            onChange={handleSearchChange}
                                        />
                                        <button className="btn btn-default" title="Reload" onClick={fetchProducts}>
                                            <i className="fas fa-sync-alt"></i>
                                        </button>
                                        <PDFDownloadLink document={<ProductPDF products={products} />} fileName="products.pdf">
                                            <button className="btn btn-default" title="Pdf"><i className="fas fa-file-pdf"></i></button>
                                        </PDFDownloadLink>
                                        <CSVLink data={filteredProducts} filename={"products.csv"}>
                                            <button className="btn btn-default" title="Excel"><i className="fas fa-file-excel"></i></button>
                                        </CSVLink>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="panel-body table-responsive">
                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>Image</th>
                                        <th>Name</th>
                                        <th>Category</th>
                                        <th>Price</th>
                                        <th>Description</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredProducts.map((product, index) => (
                                        <tr key={product._id}>
                                            <td>{index + 1}</td>
                                            <td><img height="100px" width="100px" src={product.image} alt={product.name} /></td>
                                            <td>{product.name}</td>
                                            <td>{product.category}</td>
                                            <td>{product.price}</td>
                                            <td>{product.description}</td>
                                            <td className="action-icons">
                                                <Link to={`/editProduct/${product._id}`} className="edit-icon" title="Edit">
                                                    <i className="fa fa-edit"></i>
                                                </Link>
                                                <a href="#" className="delete-icon" onClick={() => removeItem(product._id)} title="Delete">
                                                    <img src={crossIcon} alt="Delete" style={{ height: '25px', width: '30px' }} />
                                                </a>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                        <div className="panel-footer">
                            <div className="row">
                                <div className="col col-sm-6 col-xs-6">Showing <b>{filteredProducts.length}</b> out of <b>{products.length}</b> entries</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ListProduct;
