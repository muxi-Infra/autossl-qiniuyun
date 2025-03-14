package cron

type Corn interface {
	Start()
}

func NewCorn(q *QiniuSSL) Corn {
	return q
}
