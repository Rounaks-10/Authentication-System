import { createContext, useEffect, useState } from "react"
import { toast } from "react-toastify"
import axios from "axios"
export const AppContent = createContext()

export const AppContextProvider =(props)=>{
    axios.defaults.withCredentials=true
    const backendurl = import.meta.env.VITE_BACKEND_URL
    const [isLoggedin,setIsLoggedin] =useState(false)
    const [userData,SetUserData] =useState(false)
    const getAuthState =async()=>{
        try {
            const {data} =await axios.get(backendurl+'/api/user/is-auth')
            if(data.success){
                setIsLoggedin(true)
                getUserData()
            }
        } catch (error) {
            toast.error(error.message)
        }
    }
    const getUserData =async ()=>{
        try {
            const {data} =await axios.get(backendurl+'/api/user/data')
            data.success? SetUserData(data.userData) : toast.error(data.message)
        } catch (error) {
            toast.error(error.message)
        }
    }
    useEffect(()=>{
        getAuthState();
    },[])
    const value={
        backendurl,
        isLoggedin,setIsLoggedin,
        userData,SetUserData,
        getUserData
    }
    return(
        <AppContent.Provider value={value}>
            {props.children}

        </AppContent.Provider>
    )
}