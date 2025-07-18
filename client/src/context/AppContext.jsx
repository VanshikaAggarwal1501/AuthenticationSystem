import { useState, useEffect } from "react";
import { createContext } from "react";
import axios from "axios";
import { toast } from "react-toastify";

export const AppContext= createContext();
export const AppContextProvider= (props) => {
    axios.defaults.withCredentials= true;
    const backendUrl= import.meta.env.VITE_BACKEND_URL;
    console.log(backendUrl);
    const [isLoggedin, setIsLoggedin]= useState(false);
    const [userData, setUserData]= useState(false);

    const getAuthState= async() => {
        try{
            const {data}= await axios.get(backendUrl + '/api/auth/is-auth');
            if(data.success) {
                console.log(data); 
                toast.success(data.message);
                setIsLoggedin(true);
                getUserData();
            } else {
                toast.error(data.message);
            }
        } catch(error) {
            toast.error(error.message);
        }
    }
    const getUserData= async()=>{
        try{
            const {data}= await axios.get(backendUrl+ '/api/user/data');
            data.success ? setUserData(data.userData) : toast.error(data.message)
        } catch(error) {
            toast.error(error.message);
        }
    }
    useEffect(()=> {
        getAuthState();
    }, [])
    const value= {
        backendUrl,
        isLoggedin, setIsLoggedin,
        userData, setUserData,
        getUserData

    }
    return (
        <AppContext.Provider value= {value}>
            {props.children}

        </AppContext.Provider>
    )
}