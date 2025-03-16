package response

type Resp struct {
	Code    int
	Message string
	Data    any
}

type GetConfResp struct {
	Conf string `json:"conf"`
}
