#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_NOTES 100
#define MAX_TITLE_LEN 50
#define MAX_CONTENT_LEN 500
#define FILENAME "notes.dat"

// Note structure
typedef struct {
    int id;
    char title[MAX_TITLE_LEN];
    char content[MAX_CONTENT_LEN];
    char date[20];
    int isDeleted;  // Flag to mark if note is deleted
} Note;

// Global variables
Note notes[MAX_NOTES];
int noteCount = 0;
int lastId = 0;

// Function declarations
void loadNotes();
void saveNotes();
void addNote();
void deleteNote();
void updateNote();
void searchNote();
void listAllNotes();
void getCurrentDate(char *dateStr);
void clearInputBuffer();
int findNoteById(int id);
void printNote(Note note);
void printMenu();

int main() {
    loadNotes();  // Load existing notes
    
    int choice;
    do {
        printMenu();
        scanf("%d", &choice);
        clearInputBuffer();
        
        switch(choice) {
            case 1:
                addNote();
                break;
            case 2:
                deleteNote();
                break;
            case 3:
                updateNote();
                break;
            case 4:
                searchNote();
                break;
            case 5:
                listAllNotes();
                break;
            case 0:
                saveNotes();
                printf("Thank you for using Note Manager! Goodbye!\n");
                break;
            default:
                printf("Invalid choice, please try again.\n");
        }
    } while(choice != 0);
    
    return 0;
}

// Print menu
void printMenu() {
    printf("\n===== Note Manager =====\n");
    printf("1. Add Note\n");
    printf("2. Delete Note\n");
    printf("3. Update Note\n");
    printf("4. Search Note\n");
    printf("5. List All Notes\n");
    printf("0. Exit\n");
    printf("Please select an operation: ");
}

// Clear input buffer
void clearInputBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// Get current date
void getCurrentDate(char *dateStr) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    sprintf(dateStr, "%04d-%02d-%02d", 
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);
}

// Load notes data
void loadNotes() {
    FILE *file = fopen(FILENAME, "rb");
    if (file == NULL) {
        printf("Note file not found, creating new file.\n");
        return;
    }
    
    noteCount = 0;
    lastId = 0;
    
    while (fread(&notes[noteCount], sizeof(Note), 1, file) == 1 && noteCount < MAX_NOTES) {
        if (notes[noteCount].id > lastId) {
            lastId = notes[noteCount].id;
        }
        noteCount++;
    }
    
    fclose(file);
    printf("Successfully loaded %d notes.\n", noteCount);
}

// Save notes data
void saveNotes() {
    FILE *file = fopen(FILENAME, "wb");
    if (file == NULL) {
        printf("Cannot open file to save notes.\n");
        return;
    }
    
    for (int i = 0; i < noteCount; i++) {
        if (!notes[i].isDeleted) {
            fwrite(&notes[i], sizeof(Note), 1, file);
        }
    }
    
    fclose(file);
    printf("Notes have been saved.\n");
}

// Add note
void addNote() {
    if (noteCount >= MAX_NOTES) {
        printf("Maximum number of notes reached, cannot add more.\n");
        return;
    }
    
    Note newNote;
    newNote.id = ++lastId;
    newNote.isDeleted = 0;
    
    printf("Enter note title: ");
    fgets(newNote.title, MAX_TITLE_LEN, stdin);
    newNote.title[strcspn(newNote.title, "\n")] = 0;  // Remove newline
    
    printf("Enter note content: ");
    fgets(newNote.content, MAX_CONTENT_LEN, stdin);
    newNote.content[strcspn(newNote.content, "\n")] = 0;  // Remove newline
    
    getCurrentDate(newNote.date);
    
    notes[noteCount++] = newNote;
    printf("Note added, ID: %d\n", newNote.id);
    saveNotes();
}

// Find note
int findNoteById(int id) {
    for (int i = 0; i < noteCount; i++) {
        if (notes[i].id == id && !notes[i].isDeleted) {
            return i;
        }
    }
    return -1;
}

// Print note
void printNote(Note note) {
    printf("ID: %d\n", note.id);
    printf("Title: %s\n", note.title);
    printf("Content: %s\n", note.content);
    printf("Date: %s\n", note.date);
    printf("-----------------------\n");
}

// Delete note
void deleteNote() {
    int id;
    printf("Enter the ID of note to delete: ");
    scanf("%d", &id);
    clearInputBuffer();
    
    int index = findNoteById(id);
    if (index == -1) {
        printf("Note does not exist.\n");
        return;
    }
    
    notes[index].isDeleted = 1;
    printf("Note has been deleted.\n");
    saveNotes();
}

// Update note
void updateNote() {
    int id;
    printf("Enter the ID of note to update: ");
    scanf("%d", &id);
    clearInputBuffer();
    
    int index = findNoteById(id);
    if (index == -1) {
        printf("Note does not exist.\n");
        return;
    }
    
    printf("Current note content:\n");
    printNote(notes[index]);
    
    printf("Enter new title (leave empty to keep unchanged): ");
    char newTitle[MAX_TITLE_LEN];
    fgets(newTitle, MAX_TITLE_LEN, stdin);
    newTitle[strcspn(newTitle, "\n")] = 0;
    
    printf("Enter new content (leave empty to keep unchanged): ");
    char newContent[MAX_CONTENT_LEN];
    fgets(newContent, MAX_CONTENT_LEN, stdin);
    newContent[strcspn(newContent, "\n")] = 0;
    
    if (strlen(newTitle) > 0) {
        strcpy(notes[index].title, newTitle);
    }
    
    if (strlen(newContent) > 0) {
        strcpy(notes[index].content, newContent);
    }
    
    printf("Note has been updated.\n");
    saveNotes();
}

// Search note
void searchNote() {
    printf("1. Search by ID\n");
    printf("2. Search by title keyword\n");
    printf("Choose search method: ");
    
    int choice;
    scanf("%d", &choice);
    clearInputBuffer();
    
    if (choice == 1) {
        int id;
        printf("Enter note ID: ");
        scanf("%d", &id);
        clearInputBuffer();
        
        int index = findNoteById(id);
        if (index == -1) {
            printf("Note does not exist.\n");
            return;
        }
        
        printf("\nMatching note found:\n");
        printNote(notes[index]);
    } 
    else if (choice == 2) {
        char keyword[MAX_TITLE_LEN];
        printf("Enter title keyword: ");
        fgets(keyword, MAX_TITLE_LEN, stdin);
        keyword[strcspn(keyword, "\n")] = 0;
        
        int found = 0;
        printf("\nFound notes:\n");
        
        for (int i = 0; i < noteCount; i++) {
            if (!notes[i].isDeleted && strstr(notes[i].title, keyword) != NULL) {
                printNote(notes[i]);
                found = 1;
            }
        }
        
        if (!found) {
            printf("No matching notes found.\n");
        }
    } 
    else {
        printf("Invalid choice.\n");
    }
}

// List all notes
void listAllNotes() {
    int count = 0;
    printf("\nAll notes:\n");
    
    for (int i = 0; i < noteCount; i++) {
        if (!notes[i].isDeleted) {
            printNote(notes[i]);
            count++;
        }
    }
    
    if (count == 0) {
        printf("No notes available.\n");
    } else {
        printf("Total %d notes.\n", count);
    }
}