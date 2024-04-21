import React, { useState } from 'react';
import Navbar from './component/Navbar/Navbar';
import Admin from './pages/admin/Admin';
// import Navbar from './component/Navbar/Navbar';
// import Navbar from './component/Navbar/navbar';

const App = () => {
  // const [isLoggedIn, setIsLoggedIn] = useState(false);
  return (
    <div>
      <Navbar />
      <Admin />
      {/* <Admin setIsLoggedIn={setIsLoggedIn} /> */}
    </div>
  )
}

export default App