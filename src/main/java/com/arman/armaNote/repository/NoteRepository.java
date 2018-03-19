package com.arman.armaNote.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.arman.armaNote.model.Note;

@Repository("noteRepository")
public interface NoteRepository extends JpaRepository<Note, Long> {

}
