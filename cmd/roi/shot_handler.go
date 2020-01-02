package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/studio2l/roi"
)

func addShotHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	if r.Method == "POST" {
		return addShotPostHandler(w, r, env)
	}
	w.Header().Set("Cache-control", "no-cache")
	cfg, err := roi.GetUserConfig(DB, env.SessionUser.ID)
	if err != nil {
		return err
	}
	id := r.FormValue("id")
	if id == "" {
		// 요청이 프로젝트를 가리키지 않을 경우 사용자가
		// 보고 있던 프로젝트를 선택한다.
		id = cfg.CurrentShow
		if id == "" {
			// 사용자의 현재 프로젝트 정보가 없을때는
			// 첫번째 프로젝트를 가리킨다.
			shows, err := roi.AllShows(DB)
			if err != nil {
				return err
			}
			if len(shows) == 0 {
				return roi.BadRequest("no shows in roi")
			}
			id = shows[0].Show
		}
		http.Redirect(w, r, "/add-shot?id="+id, http.StatusSeeOther)
		return nil
	}
	sw, err := roi.GetShow(DB, id)
	if err != nil {
		return err
	}
	cfg.CurrentShow = id
	err = roi.UpdateUserConfig(DB, env.SessionUser.ID, cfg)
	if err != nil {
		return err
	}

	recipe := struct {
		LoggedInUser string
		Show         *roi.Show
	}{
		LoggedInUser: env.SessionUser.ID,
		Show:         sw,
	}
	return executeTemplate(w, "add-shot.html", recipe)
}

func addShotPostHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	err := mustFields(r, "id", "shot")
	if err != nil {
		return err
	}
	id := r.FormValue("id")
	shot := r.FormValue("shot")
	sh, err := roi.GetShow(DB, id)
	if err != nil {
		return err
	}
	s := &roi.Shot{
		Show:         id,
		Shot:         shot,
		Status:       roi.ShotWaiting,
		WorkingTasks: sh.DefaultTasks,
	}
	err = roi.AddShot(DB, s)
	if err != nil {
		return err
	}
	for _, task := range sh.DefaultTasks {
		t := &roi.Task{
			Show:    id,
			Shot:    shot,
			Task:    task,
			Status:  roi.TaskInProgress,
			DueDate: time.Time{},
		}
		err := roi.AddTask(DB, t)
		if err != nil {
			return err
		}
	}
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
	return nil
}

func updateShotHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	if r.Method == "POST" {
		return updateShotPostHandler(w, r, env)
	}
	err := mustFields(r, "id")
	if err != nil {
		return err
	}
	id := r.FormValue("id")
	err = roi.VerifyShotID(id)
	if err != nil {
		return err
	}
	s, err := roi.GetShot(DB, id)
	if err != nil {
		return err
	}
	ts, err := roi.ShotTasks(DB, id)
	if err != nil {
		return err
	}
	tm := make(map[string]*roi.Task)
	for _, t := range ts {
		tm[t.Task] = t
	}
	recipe := struct {
		LoggedInUser  string
		Shot          *roi.Shot
		AllShotStatus []roi.ShotStatus
		Tasks         map[string]*roi.Task
		AllTaskStatus []roi.TaskStatus
		Thumbnail     string
	}{
		LoggedInUser:  env.SessionUser.ID,
		Shot:          s,
		AllShotStatus: roi.AllShotStatus,
		Tasks:         tm,
		AllTaskStatus: roi.AllTaskStatus,
		Thumbnail:     "data/show/" + id + "/thumbnail.png",
	}
	return executeTemplate(w, "update-shot.html", recipe)
}

func updateShotPostHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	err := mustFields(r, "id")
	if err != nil {
		return err
	}
	id := r.FormValue("id")
	show, shot, err := roi.SplitShotID(id)
	if err != nil {
		return err
	}
	tasks := fieldSplit(r.FormValue("working_tasks"))
	tforms, err := parseTimeForms(r.Form, "due_date")
	if err != nil {
		return err
	}
	upd := roi.UpdateShotParam{
		Status:        roi.ShotStatus(r.FormValue("status")),
		EditOrder:     atoi(r.FormValue("edit_order")),
		Description:   r.FormValue("description"),
		CGDescription: r.FormValue("cg_description"),
		TimecodeIn:    r.FormValue("timecode_in"),
		TimecodeOut:   r.FormValue("timecode_out"),
		Duration:      atoi(r.FormValue("duration")),
		Tags:          fieldSplit(r.FormValue("tags")),
		WorkingTasks:  tasks,
		DueDate:       tforms["due_date"],
	}
	err = roi.UpdateShot(DB, id, upd)
	if err != nil {
		return err
	}
	// 샷에 등록된 태스크 중 기존에 없었던 태스크가 있다면 생성한다.
	for _, task := range tasks {
		_, err := roi.GetTask(DB, id+"/"+task)
		if err != nil {
			if !errors.As(err, &roi.NotFoundError{}) {
				return err
			} else {
				t := &roi.Task{
					Show:    show,
					Shot:    shot,
					Task:    task,
					Status:  roi.TaskInProgress,
					DueDate: time.Time{},
				}
				err = roi.AddTask(DB, t)
				if err != nil {
					return err
				}
			}
		}
	}
	err = saveImageFormFile(r, "thumbnail", fmt.Sprintf("data/show/%s/%s/thumbnail.png", show, shot))
	if err != nil {
		return err
	}
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
	return nil
}
