import React, { useState, useEffect } from 'react';
import './payment.css'
function Orders() {
    const [orders, setOrders] = useState([]);

    useEffect(() => {
        fetchOrders();
    }, []);

    const fetchOrders = async () => {
        try {
            const response = await fetch(`http://localhost:8081/orders`);
            if (response.ok) {
                const ordersData = await response.json();
                setOrders(ordersData);
            } else {
                throw new Error('Failed to fetch orders');
            }
        } catch (error) {
            console.error(error);
        }
    };

    const handleStatusChange = async (orderId, status) => {
        try {
            await fetch(`http://localhost:8081/orders/${orderId}/status`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ status: status }),
            });
            // Update the orders list after status change
            fetchOrders();
        } catch (error) {
            console.error(error);
        }
    };

    return (
        <div>
            <h1>Admin Orders</h1>
            <div className='mr'>
                <div className="container">
                    <div className="row main">
                        <div className="col-md-offset-1 col-md-10">
                            <div className="panel">
                                <div className="panel-body table-responsive">
                                    <table className="table">
                                        <thead>
                                            <tr>
                                                <th>#</th>
                                                <th>Order ID</th>
                                                <th>Order Date</th>
                                                <th>Total Price</th>
                                                <th>Status</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {orders.map((order, index) => (
                                                <tr key={order._id}>
                                                    <td>{index + 1}</td>
                                                    <td>{order._id}</td>
                                                    <td>{order.orderDate}</td>
                                                    <td>{order.totalPrice}</td>
                                                    <td>Status: {order.status}</td>
                                                    <td>
                                                        <select
                                                            value={order.status}
                                                            onChange={(e) => handleStatusChange(order._id, e.target.value)}
                                                        >
                                                            <option value="pending">Pending</option>
                                                            <option value="delivered">Delivered</option>
                                                            <option value="success">Success</option>
                                                        </select>
                                                    </td>
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
    );
}

export default Orders;
