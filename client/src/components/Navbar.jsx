import React, { useContext } from 'react'
import {assets} from '../assets/assets.js'
import { useNavigate } from 'react-router-dom'
import { AppContext } from '../context/AppContext.jsx';
import axios from 'axios';
import { toast } from 'react-toastify';

const Navbar = () => {
    const navigate= useNavigate();
    const {userData, backendUrl, setUserData, setIsLoggedin} = useContext(AppContext);
    const sendVerificationOtp= async()=> {
      try{
        axios.defaults.withCredentials = true;
        const {data}= await axios.post(backendUrl+ '/api/auth/send-verify-otp');
        if(data.success){
          navigate('/email-verify');
          toast.success(data.message);
        } else {
          toast.error(data.message);
        }

      } catch(error) {
        toast.error(error.message);
      }
    }
    const logout= async()=>{
      try{
        axios.defaults.withCredentials = true;
        const {data}= await axios.post(backendUrl+ '/api/auth/logout');
        if(data.success) {
          console.log(data); 
          toast.success(data.message);
          setIsLoggedin(false);
          setUserData(false);
          navigate('/');
        }
      } catch(error) {
        toast.error(error.message);
      }
    }
  return (
    <div className='w-full flex justify-between items-center p-4 sm:p-6 sm:px-24 absolute top-0'>
        <img className='w-28 sm:w-32' src={assets.logo} alt="" />
        {userData ? <div className='flex justify-center items-center rounded-full bg-black text-white relative group w-8 h-8'>
          {userData.name[0].toUpperCase()}
          <div className='absolute hidden group-hover:block top-0 right-0 z-10 text-black rounded pt-10'>
            <ul className='m-0 p-2 list-none bg-gray-200 text-sm'>
              {!userData.isAccountVerified &&  <li onClick={sendVerificationOtp} className='py-1 px-2 hover:bg-gray-200 cursor-pointer'>Verify Email</li>}
              <li onClick={logout} className='py-1 px-2 hover:bg-gray-200 cursor-pointer pr-10'>Logout</li>
            </ul>
          </div>
        </div> :
          <button onClick={()=>navigate('/login')} 
          className='flex items-center gap-2 border border-gray-500 rounded-full px-6 py-2 text-gray-800 hover:bg-gray-100'>
            Login <img src={assets.arrow_icon} alt="" /></button>
        }
       
      
    </div>
  )
}

export default Navbar
