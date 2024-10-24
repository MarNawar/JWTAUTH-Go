package helpers

import (
    "errors"
    "github.com/gin-gonic/gin"
)

func CheckUserType(c *gin.Context, role string) (err error) {
    userType := c.GetString("user_type")
    
    if userType != role {
        err = errors.New("unauthorized to access this resource")
        return err
    }

    return nil
}

func MatchUserToUid(c *gin.Context, userId string) (err error) {
    userType := c.GetString("user_type")
    uid := c.GetString("uid")
    
    if userType == "USER" && uid != userId {
        err = errors.New("unauthorized to access this resource")
        return err
    }

	err = CheckUserType(c, userType)
    return err
}
